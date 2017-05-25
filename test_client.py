#import sense_hat
from secure_api import send_message, init
import socket
import random
import time

# This client's IP.
client_ip = socket.gethostbyname("localhost")

# The server to connect to.
server_ip, server_port = "192.168.1.38", 8081

def send_humidity(user, port):
    #humidity = sense.get_humidity()
    while True:
        humidity = random.randrange(20, 25)
        send_message(str(humidity), user, port)
        time.sleep(5)

if __name__ == '__main__':
    init(client_ip)
    send_humidity(server_ip, server_port) # todo remember to change this to be more general