#import sense_hat
from secure_api import send_message, init

#sense = sense_hat.SenseHat()
server_ip, server_port = "192.168.1.101", 8080

def send_humidity(user):
    #humidity = sense.get_humidity()
    humidity = 10
    send_message(str(humidity), user, server_port)

if __name__ == '__main__':
    init()
    send_humidity(server_ip)