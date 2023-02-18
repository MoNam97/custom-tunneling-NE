import socket
import threading

M_FORMAT = 'ascii'

ip = '127.0.0.12'
port = 12000

tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_socket.bind((ip, port))


def handle_tcp_xclient_send(Xclient, server_socket):
    print("handle_tcp_xclient_send :)))))))))))))))")
    while True:
        try:
            response = server_socket.recv(4096).decode(M_FORMAT)
            if response == '':
                print("server_socket closed")
                # Xclient.close()
                break
            print(f'response:\t{response}\n')
            response = "HTTP/1.1 200 OK\n\n$|$" + response
            Xclient.sendall(response.encode(M_FORMAT))
        except Exception as e:
            print('TCP connection failed...send\n %s' % e)
            Xclient.close()
            server_socket.close()
            break


def handle_tcp_xclient_recv(Xclient, addr):
    print(f'\nnew TCP connection from {addr}\n')
    first_message_flag = 0
    server_socket = None
    while True:
        try:
            request = Xclient.recv(4096).decode(M_FORMAT)
            print(f'request:\t{request}\n')

            rmt_addr = request.split('\n\n$|$')[0]
            rmt_addr = rmt_addr.split(':')[1]  # (ip, port)
            print(f'rmt_addr:\t{rmt_addr}')
            server_ip = rmt_addr.split(',')[0].replace('(', '')[1:-1]
            server_port = int(rmt_addr.split(', ')[1].replace(')', ''))
            data = request.split('\n\n$|$')[1]
            if first_message_flag == 0:
                print("new server connection")
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                print(f'connecting to {server_ip}:{server_port}')
                server_socket.connect((server_ip, server_port))
                first_message_flag = 1
                threading.Thread(target=handle_tcp_xclient_send, args=(Xclient, server_socket)).start()

            server_socket.send(data.encode(M_FORMAT))
            # Xclient.send(('I received the following response for request:\n' + request).encode(M_FORMAT))
        except Exception as e:
            print(f'TCP connection failed...recv\n{e}')
            Xclient.close()
            break
    print("break from the while loop :\\")

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
    tcp_socket.listen(1)
    print('Xserver listening...')
    try:
        while True:
            Xclient, addr = tcp_socket.accept()
            # print(f'connection:\t{Xclient}, {addr}')
            threading.Thread(target=handle_tcp_xclient_recv, args=(Xclient, addr)).start()
            # threading.Thread(target=handle_tcp_xclient_send, args=(Xclient, )).start()
    except Exception as e:
        print('Failed...{}'.format(e))
