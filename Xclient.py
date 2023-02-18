import multiprocessing as mp
import socket
import logging
import threading

import numpy as np
from queue import Queue
import ssl
import time
import sys
import argparse
import random
import time

import os

incoming_udp_queue = Queue()
outgoing_udp_queue = Queue()

M_FORMAT = 'ascii'


def parse_input_argument():
    parser = argparse.ArgumentParser(description='This is a client program that create a tunnel\
                                                  to the server over various TCP connections.')

    parser.add_argument('-ut', '--udp-tunnel', action='append', required=True,
                        help="Make a tunnel from the client to the server. The format is\
                              'listening ip:listening port:remote ip:remote port'.")
    parser.add_argument('-s', '--server', required=True,
                        help="The IP address and (TCP) port number of the tunnel server.\
                               The format is 'server ip:server port'.")
    parser.add_argument('-v', '--verbosity', choices=['error', 'info', 'debug'], default='info',
                        help="Determine the verbosity of the messages. The default value is 'info'.")

    args = parser.parse_args()
    print(args)
    print(type(args))
    return args


def read_n_byte_from_tcp_sock(sock, n):
    '''Just for read n byte  from tcp socket'''

    buff = bytearray(n)
    pos = 0
    while pos < n:
        cr = sock.recv_into(memoryview(buff)[pos:])
        if cr == 0:
            raise EOFError
        pos += cr
    return buff


def handle_tcp_conn_recv(tcp_socket, udp_socket, incom_udp_addr):
    """
    read from tcp socket for the UDP segment received through the tunnel,
    then forward received segment to incom_udp_addr
    """
    while True:
        try:
            data = tcp_socket.recv(1024)
            # data = read_n_byte_from_tcp_sock(tcp_socket, 4096)
            data = data.decode(M_FORMAT).split("\n\n$|$")[1]
            # data = data.decode(M_FORMAT)
            print(f"received TCP segment from {tcp_socket.getpeername()}")
            print(f"segment:\t{data}\n")
            incoming_udp_queue.put(data)
        except Exception as ce:  # ConnectionError
            print(ce)
            break


def handle_tcp_conn_send(tcp_socket: socket.socket, rmt_udp_addr):
    """
    get remote UDP ip and port(rmt_udp_addr) and Concat them then sending it to the TCP socket
    after that read from udp_to_tcp_queue for sendeig a UDP segment and update queue,
    don't forgot to block the queue when you are reading from it.
    """
    # requests are decoded
    while True:
        try:
            if not outgoing_udp_queue.empty():
                data = outgoing_udp_queue.get()
                segment = "GET /index.html HTTP/1.1\nAddr:" + str(rmt_udp_addr) + "\n\n$|$" + data
                print(f"segment:\n{segment}\n")
                # tcp_socket.sendall(data, (rmt_udp_addr))
                tcp_socket.sendall(segment.encode(M_FORMAT))
        except Exception as ce:  # ConnectionError
            print("TLS Connection error {}".format(ce))
            break


def handle_udp_conn_send(udp_socket: socket.socket, app_udp_addr):
    # responses are decoded
    while True:
        try:
            if not incoming_udp_queue.empty():
                data = incoming_udp_queue.get()
                udp_socket.sendto(data.encode(M_FORMAT), app_udp_addr)
        except Exception as ce:
            print("UDP Connection error {}".format(ce))
            break


def handle_udp_conn_recv(udp_socket, tcp_server_addr, rmt_udp_addr):
    """
        This function should be in while True,
        Receive a UDP packet form incom_udp_addr.
        It also keeps the associated thread for handling tcp connections in udp_conn_list,
        if incom_udp_addr not in udp_conn_list, Recognize a new UDP connection from incom_udp_addr.
        So establish a TCP connection to the remote server for it
        and if incom_udp_addr in udp_conn_list you should continue sending in esteblished socekt  ,
        you need a queue for connecting udp_recv thread to tcp_send thread.
    """
    first_connection = True
    print(f"udp_conn_recv pid:\t{os.getpid()}\ntcp_server_addr:\t{tcp_server_addr}\nrmt_udp_addr:\t{rmt_udp_addr}")
    try:
        while True:

            request, address = udp_socket.recvfrom(1024)
            if first_connection is True:
                print(f'new udp connection from {address}')
                tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp_socket.connect(tcp_server_addr)
                first_connection = False
                threading.Thread(target=handle_tcp_conn_recv, args=(tcp_socket, udp_socket, address)).start()
                threading.Thread(target=handle_tcp_conn_send,
                                 args=(tcp_socket, rmt_udp_addr)).start()
                threading.Thread(target=handle_udp_conn_send, args=(udp_socket, address)).start()

            request = request.decode(M_FORMAT)
            print(f'received UDP request from client {address}')
            print(f'request:\t{request}\n')
            outgoing_udp_queue.put(request)

            ################################################
            # print(f"{os.getpid()}\nudp_conn_list: {udp_conn_list}\n")
            # for item in incoming_udp_list:
            #     print(item)
            # print("_____________\n")

            # udp_socket.sendto("message received\n".encode(M_FORMAT), address)
    except KeyboardInterrupt:
        print("Closing the UDP connection...")


if __name__ == "__main__":
    print("main pid:\t" + str(os.getpid()))

    args = parse_input_argument()

    tcp_server_ip = args.server.split(':')[0]
    tcp_server_port = int(args.server.split(':')[1])
    tcp_server_address = (tcp_server_ip, tcp_server_port)

    if args.verbosity == 'error':
        log_level = logging.ERROR
    elif args.verbosity == 'info':
        log_level = logging.INFO
    elif args.verbosity == 'debug':
        log_level = logging.DEBUG
    else:
        print('Invalid verbosity level.')
        log_level = logging.ERROR
    conn_format = "%(asctime)s: (%(levelname)s) %(message)s"
    logging.basicConfig(format=conn_format, level=log_level, datefmt="%H:%M:%S")

    for tun_addr in args.udp_tunnel:
        tun_addr_split = tun_addr.split(':')
        udp_listening_ip = tun_addr_split[0]
        udp_listening_port = int(tun_addr_split[1])
        rmt_udp_ip = tun_addr_split[2]
        rmt_udp_port = int(tun_addr_split[3])
        rmt_udp_address = (rmt_udp_ip, rmt_udp_port)

        try:
            udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            udp_socket.bind((udp_listening_ip, udp_listening_port))
        except socket.error as e:
            logging.error("(Error) Error openning the UDP socket: {}".format(e))
            logging.error(
                "(Error) Cannot open the UDP socket {}:{} or bind to it".format(udp_listening_ip, udp_listening_port))
            sys.exit(1)
        else:
            logging.info("Bind to the UDP socket {}:{}".format(udp_listening_ip, udp_listening_port))

        mp.Process(target=handle_udp_conn_recv,
                   args=(udp_socket, tcp_server_address, rmt_udp_address)).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Closing the TCP connection...")
