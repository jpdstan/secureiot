from uuid import getnode as get_mac
from secure_server import register_client
from crypto import Crypto

import socket
import requests

crypto = Crypto()
mac_addr = get_mac()
pub_key, priv_key = None, None

# SecureIOT server IP address
server_ip, server_port = "127.0.0.1", "8080"

# Key-value of shared_secrets between other clients.
shared_secrets = {}

# Send MSG to USER, an IP address. To be used on clients that need to send data to the server.
def send_message(msg, user, port):
    if not shared_secrets[user]:
        user_pub_key = request_user_pk(user)
        if user_pub_key is None:
            print("Requested user does not exist in the database.")
            pass
        shared_secrets[user] = priv_key ^ user_pub_key # todo: use DHE

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

# Request USER's public key from the server.
def request_user_pk(user):
    response = requests.get(server_ip + ":" + server_port + "/user_pk?q=" + user)
    if response.code == 200:
        return response.content
    return None

# Add USER to known hosts (~/.ssh/known_hosts).
def add_known_host(user):
    pass

# Register this machine with the server with generated public key.
def init():
    # Request this users public key from the SecureIoT server.
    global pub_key
    global priv_key

    pub_key = request_user_pk(mac_addr)

    # This MAC address has not registered with our service.
    if pub_key is None:
        print("Performing key generation, saving, and loading")
        pub_key, priv_key = crypto.gen_asymmetric_keypair(2048)
        crypto.save_keyfile("user", priv_key)
        key_loaded = crypto.load_keyfile("user")
        assert priv_key == key_loaded

        register_client(mac_addr, pub_key)
    else:
        priv_key = crypto.load_keyfile("user")
    pass

class IntegrityError(RuntimeError):
    """Error to raise whenever an integrity error is encountered."""
    pass