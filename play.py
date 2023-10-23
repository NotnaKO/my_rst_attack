import logging
import random
import socket
import time
from logging import debug
from socket import create_connection
from socketserver import ThreadingTCPServer, BaseRequestHandler
from threading import Thread


def a_func(sock: socket.socket, addr: (int, int)):
    while True:
        try:
            sock.sendall(b"begin")
        except ConnectionResetError:
            logging.info("Successful RST attack")
            break
        debug(f"Message from client {addr} sent")
        data = sock.recv(1024)
        if not data:
            break
        expected = f"{addr[0]}+{addr[1]}".encode("utf-8")
        if data != expected:
            logging.error(data)
        assert expected == data
        debug(f"Client {addr} finished iteration")

        time.sleep(1)
    sock.close()


class Handler(BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        while True:
            try:
                data = self.request.recv(1024)
            except TimeoutError:
                logging.info("Server timeout")
                break
            debug(f"Server get {data}")
            if not data:
                break
            if data != b"begin":
                logging.error(data)
            assert data == b"begin"
            debug(f"Server get data from {self.client_address}")
            self.request.sendto(
                f"{self.client_address[0]}+{self.client_address[1]}".encode("utf-8"),
                self.client_address)
            debug("Server finished iteration")


def b_func(server: ThreadingTCPServer):
    debug("Starting server")
    server.serve_forever(0.5)


used_ports = set()


def generate_port():
    while True:
        port = random.randrange(25000, 30000)
        if port not in used_ports:
            break
    used_ports.add(port)
    return port


def generate_address():
    return f'127.0.0.1', generate_port()


def play(a_addr, b_addr):
    with ThreadingTCPServer(b_addr, Handler, True) as server:
        b = Thread(target=b_func, args=[server], daemon=True, name="B")
        b.start()

        with create_connection(b_addr, source_address=a_addr) as a_sock:
            debug("Created connection")
            a = Thread(target=a_func, args=[a_sock, a_addr], daemon=True, name="A")
            a.start()

            a.join(15)
            b.join(15)


if __name__ == '__main__':
    play(generate_address(), generate_address())
