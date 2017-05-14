from secure_server import register_client
from crypto import Crypto

from diffiehellman.diffiehellman import DiffieHellman
import socket
import requests

crypto = Crypto()
client_ip_addr = "192.168.1.38"
dhe_keys, pub_key, priv_key = None, None, None

# SecureIOT server IP address
server_ip, server_port = "127.0.0.1", 8080

# Key-value of shared_secrets between other clients.
shared_secrets = {}

# Send MSG to USER, an IP address. To be used on clients that need to send data to the server.
def send_message(msg, user, port):
    if not user in shared_secrets:
        user_pub_key = request_user_pk(user)
        if user_pub_key is None:
            print("Requested user does not exist in the database.")
            pass
        shared_secrets[user] = dhe_keys.generate_shared_secret(user_pub_key) # todo: use DHE

    enc_msg = crypto.symmetric_encrypt(msg, shared_secrets[user])
    mac_sig = crypto.message_authentication_code(msg, shared_secrets[user])

    # Send message to the intended client
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    send_socket.bind((user, port))
    send_socket.listen(1)
    client_connection, client_address = send_socket.listen()
    client_connection.sendall(enc_msg + "&" + mac_sig)
    client_connection.close()

# Decrypt messages from incoming client writes. To be used on the server side.
def receive_message(msg, user):
    enc_msg, mac_sig = msg.split("&")
    dec_msg = crypto.symmetric_decrypt(enc_msg, shared_secrets[user])
    if not mac_sig == crypto.message_authentication_code(msg, shared_secrets[user]):
        raise IntegrityError
    return dec_msg

# Request USER's public key from the server in INT form.
def request_user_pk(user):
    response = requests.get("http://" + server_ip + ":" + str(server_port) + "/user_pk?q=" + user)
    if response.status_code == 200:
        return int(response.content)
    return None

# Add USER to known hosts (~/etc/hosts.allow).
def add_known_host(user):
    pass

# Register this machine with the server with generated public key.
def init():
    # Request this users public key from the SecureIoT server.
    global pub_key
    global priv_key
    global dhe_keys

    pub_key = request_user_pk(client_ip_addr)

    # This IP address has not registered with our service.
    if pub_key is None:
        print("Performing key generation, saving, and loading")
        dhe_keys = DiffieHellman(18, 0) # only 10 bit keys for testing purposes
        dhe_keys.generate_public_key()

        # Write private key to file on client.
        # priv_key_file = open("keys/" + client_ip_addr, "wb")
        # priv_key_file.write(bytes(str(dhe_keys.private_key, 'utf-8')))
        # priv_key_file.close()

        # Register this client's newly created public key with the SecureIoT server.
        register_client(client_ip_addr, dhe_keys.public_key)
    else:
        pass
        # Read private key from existing file.
        # priv_key_file = open("keys/" + client_ip_addr, "rb")
        # priv_key = int(str(priv_key_file.readall(), 'utf-8'))
        # priv_key_file.close()

class IntegrityError(RuntimeError):
    """Error to raise whenever an integrity error is encountered."""
    pass