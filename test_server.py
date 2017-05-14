import socket
from secure_api import receive_message, init

host, port = "", 8080

def listen():
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((host, port))
    listen_socket.listen(1)

    print('Serving HTTP on port %s ...' % port)
    while True:
        client_connection, client_address = listen_socket.accept()
        print("Received data from " + client_address)
        data = client_connection.recv(1024)
        msg = receive_message(data, client_address)

        print("decrypted message" + msg)

        client_connection.close()

if __name__ == '__main__':
    init()
    listen()