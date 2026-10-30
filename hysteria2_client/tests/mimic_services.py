"""Local echo targets for the privileged Mimic interoperability probes."""
import socket
import threading


def udp_echo(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", port))
        while True:
            data, address = sock.recvfrom(65535)
            sock.sendto(data, address)


def tcp_echo():
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", 18080))
        listener.listen()
        while True:
            connection, _ = listener.accept()
            def serve(sock):
                with sock:
                    while data := sock.recv(65535):
                        sock.sendall(data)
            threading.Thread(target=serve, args=(connection,), daemon=True).start()


for port in [4443, 18081]:
    threading.Thread(target=udp_echo, args=(port,), daemon=True).start()
tcp_echo()
