#import sense_hat
from secure_api import send_message, init
import socket
#sense = sense_hat.SenseHat()

# This client's IP.
client_ip = socket.gethostbyname("localhost")

# The server to connect to.
server_ip, server_port = "127.0.0.1", 8081

def send_humidity(user, port):
    #humidity = sense.get_humidity()
    humidity = 10
    send_message(str(humidity), user, port)

if __name__ == '__main__':
    init(client_ip)
    send_humidity(server_ip, server_port) # todo remember to change this to be more general