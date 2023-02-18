import socket, threading
from Xclient import M_FORMAT

ip = '127.0.0.12'
port = 12000

tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_socket.bind((ip, port))


def handle_tcp_xclient_send(Xclient, addr):
    Xclient.close()


def handle_tcp_xclient_recv(Xclient, addr):
    print(f'new udp connection from {addr}')
    try:
        request = Xclient.recv(4096).decode(M_FORMAT)
        print(f'request:\t{request}\n')

        rmt_addr = request.split('\n\n$|$')[0]
        rmt_addr = rmt_addr.split(':')[1]  # (ip, port)
        print(f'rmt_addr:\t{rmt_addr}')
        server_ip = rmt_addr.split(',')[0].replace('(', '')
        server_port = int(rmt_addr.split(', ')[1].replace(')', ''))
        data = request.split('\n\n$|$')[1]

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((server_ip, server_port))
        socket.send(data.encode(M_FORMAT))
        # Xclient.send(('I received the following response for request:\n' + request).encode(M_FORMAT))
    except:
        print('TCP connection failed...')
    #
    # try:
    #     while True:
    #
    #         request, address = udp_socket.recvfrom(1024)
    #         if address not in udp_conn_list:
    #             print(f'new udp connection from {address}')
    #             tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #             # tcp_socket.connect(tcp_server_addr)
    #             # tcp_socket.sendall(rmt_udp_addr)
    #             udp_conn_list[address] = tcp_socket
    #             # threading.Thread(target=handle_tcp_conn_recv, args=(tcp_socket, udp_socket, address)).start()
    #             # threading.Thread(target=handle_tcp_conn_send, args=(tcp_socket, rmt_udp_addr, outgoing_udp_queue)).start()
    #         request = request.decode(M_FORMAT)
    #         print(f'received UDP request from client {address}')
    #         print(f'request:\t{request}\n')
    #         # handle_udp_conn_recv(request)
    #         incoming_udp_queue.put((request, address))
    #         incoming_udp_list.append((request, address))
    #
    #         print(f"{os.getpid()}\nudp_conn_list: {udp_conn_list}\n")
    #         for item in incoming_udp_list:
    #             print(item)
    #         print("_____________\n")
    #
    #         udp_socket.sendto("message received\n".encode(M_FORMAT), address)
    # except KeyboardInterrupt:
    #     print("Closing the UDP connection...")


if __name__ == "__main__":
    tcp_socket.listen()
    print('Xserver listening...')
    while True:
        Xclient, addr = tcp_socket.accept()
        threading.Thread(target=handle_tcp_xclient_recv, args=(Xclient, addr))
        threading.Thread(target=handle_tcp_xclient_send, args=(Xclient, addr))
