import sense_hat
from secure_api import send_message

sense = sense_hat.SenseHat()
server_ip, server_port = "192.168.1.101", 8080

def send_humidity(user):
    humidity = sense.get_humidity()
    send_message(str(humidity), user, server_port)

if __name__ == '__main__':
 	send_humidity(server_ip)