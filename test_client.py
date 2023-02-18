import socket
import threading

M_FORMAT = 'ascii'
IP = "127.0.0.1"
PORT = int(input("Enter port: "))

xclient = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
xclient.bind((IP, PORT+1))

# xclient.connect((IP, PORT))


def udp_recv():
    while True:
        try:
            data, addr = xclient.recvfrom(1024)
            print("I got something")
            print(f"received UDP segment from {addr}")
            print(f"segment:\t{data.decode(M_FORMAT)}\n")
        except:
            print("udp_recv error")
            break


def udp_send():
    while True:
        try:
            xclient.sendto(input().encode(M_FORMAT), (IP, PORT))
        except:
            print("udp_send error")
            break


if __name__ == '__main__':
    threading.Thread(target=udp_recv).start()
    threading.Thread(target=udp_send).start()
