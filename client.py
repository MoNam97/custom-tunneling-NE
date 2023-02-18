import socket
import threading

Xclient_host = '127.0.0.1'
Xclient_port = 8010

port = int(input('Enter port:\n'))
ip = input('Enter IP:\n')


def handle_xclient_send():
    while True:
        proxy = input('Enter proxy server (Xserver.py) IP::port or 0 for default proxy:\n')

        Xserver_ip, Xserver_port = '192.168.0.24', 8080
        if proxy != '0':
            Xserver_ip, Xserver_port = proxy.split('::')[0], proxy.split('::')[1]

        url = input('Enter URL:\n')

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.settimeout(1.0)
        message = f'{ip}::{port}::{Xserver_ip}::{Xserver_port}::{url}'
        addr = (Xclient_host, Xclient_port)

        client_socket.sendto(message.encode('ascii'), addr)

        try:
            data, server = client_socket.recvfrom(1024)
            print(f'application server response:\t{data}\n')
        except socket.timeout:
            print('REQUEST TIMED OUT')


def handle_xclient_recv():
    while True:
        response, address = client_recv.recvfrom(1024)
        response = response.decode('ascii')
        print(f'server response:\t{response}')


threading.Thread(target=handle_xclient_send).start()

client_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print((ip, port))
client_recv.bind((ip, port))

threading.Thread(target=handle_xclient_recv).start()
