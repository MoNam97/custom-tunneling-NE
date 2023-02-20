import socket
import threading
import ssl

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


if __name__ == "__main__":
    tcp_socket.listen(1)
    print('Xserver listening...')
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain('xserver_certificate.crt', 'xserver_private.key')
    try:
        while True:
            Xclient, addr = tcp_socket.accept()
            tls_socket = ssl_context.wrap_socket(Xclient, server_side=True)
            # print(f'connection:\t{Xclient}, {addr}')
            threading.Thread(target=handle_tcp_xclient_recv, args=(tls_socket, addr)).start()
            # threading.Thread(target=handle_tcp_xclient_send, args=(Xclient, )).start()
    except Exception as e:
        print('Failed...{}'.format(e))
