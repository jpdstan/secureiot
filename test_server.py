import socket
from secure_api import receive_message, init

# This server's IP address and port number.
server_ip, server_port = "192.168.1.38", 8081

def listen():
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((server_ip, server_port))
    listen_socket.listen(1)

    print('Serving HTTP on port %s ...' % server_port)
    while True:
        client_connection, client_address = listen_socket.accept()
        print("Received data from " + str(client_address))
        data = client_connection.recv(1024)
        msg = receive_message(data, client_address[0])
        print("Decrypted message " + msg)
        client_connection.close()

if __name__ == '__main__':
    init(server_ip)
    listen()