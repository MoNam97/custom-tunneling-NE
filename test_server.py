import socket
import threading

M_FORMAT = 'ascii'
IP = "127.0.1.0"
PORT = int(input("Enter port: "))
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((IP, PORT))


def tcp_recv(conn: socket.socket):
    while True:
        try:
            data = conn.recv(4096).decode(M_FORMAT)
            print(f"segment:\t{data}\n")
            result = "I received your message: " + data
            conn.sendall(result.encode(M_FORMAT))
        except Exception as e:
            print(f"tcp_recv error: {e}")
            break


def tcp_send():
    while True:
        try:
            server.sendto(input().encode(M_FORMAT), (IP, PORT))
        except:
            print("tcp_send error")
            break


if __name__ == '__main__':
    server.listen(1)
    conn, addr = server.accept()
    print(f"New Connection : {conn} <-> {addr}")
    threading.Thread(target=tcp_recv, args=(conn,)).start()
    # threading.Thread(target=udp_send).start()
