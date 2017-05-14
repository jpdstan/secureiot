import sense_hat
from secure_api import send_message

sense = sense_hat.SenseHat()

def send_humidity(user):
    humidity = sense.get_humidity()
    send_message(str(humidity), user)