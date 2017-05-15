from secure_server import register_client, get_pub_key
from crypto import Crypto
from binascii import hexlify, unhexlify
import socket

# For encryption/decryption.
cipher_name = 'AES'
hash_name = 'SHA'
crypto = Crypto()
pub_key, priv_key = None, None
random = "12345"

# SecureIOT server IP address
server_ip, server_port = socket.gethostbyname("localhost"), 8080

# Key-value of shared_secrets between other clients.
shared_secrets = {}

# Send MSG to USER, an IP address. To be used on clients that need to send data to the server.
def send_message(msg, user, port):
    if not user in shared_secrets:
        user_pub_key = request_user_pk(user)
        if user_pub_key is None:
            print("Requested user does not exist in the database.")
            pass
        shared_secrets[user] = user_pub_key

    print("client side secret " + shared_secrets[user])
    enc_msg = crypto.symmetric_encrypt(msg, shared_secrets[user], cipher_name)
    print("send encrypted " + enc_msg)
    mac_sig = crypto.message_authentication_code(msg, shared_secrets[user], hash_name)

    # Send message to the intended client
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    send_socket.connect((user, port))
    send_socket.sendall(bytes(enc_msg + "&" + mac_sig, 'utf-8'))
    send_socket.close()

# Decrypt messages from incoming client writes. To be used on the server side.
def receive_message(msg, user):
    if not user in shared_secrets:
        user_pub_key = request_user_pk(user)
        if user_pub_key is None:
            print("Requested user does not exist in the database.")
            pass
        shared_secrets[user] = priv_key + user_pub_key

    print("server side secret " + shared_secrets[user])
    print(str(msg, 'utf-8'))
    enc_msg, mac_sig = str(msg, 'utf-8').split("&")

    print ("receive encrypted " + enc_msg)
    dec_msg = crypto.symmetric_decrypt(enc_msg, shared_secrets[user], cipher_name)

    #if not mac_sig == crypto.message_authentication_code(dec_msg, shared_secrets[user], hash_name):
    #    raise IntegrityError
    return dec_msg

# Request USER's public key from the server in INT form. todo not working
# def request_user_pk(user):
#     response = requests.get("http://" + server_ip + ":" + str(server_port) + "/user_pk?q=" + user)
#     print("Response from " + server_ip + " to " + user + ": " + str(response.content))
#     if response.status_code == 200:
#         return int(response.text)  # todo this is not returning anything...
#     return None

# Return key in INT form.
def request_user_pk(user):
    pub_key = get_pub_key(user)
    if pub_key is None:
        return None
    print("Retrieved pub key... " + pub_key)
    return get_pub_key(user)

# Register this machine with the server with generated public key.
def init(ip_addr):
    # Request this users public key from the SecureIoT server.
    global pub_key
    global priv_key

    pub_key = request_user_pk(ip_addr)

    # This IP address has not registered with our service.
    if pub_key is None:
        # print("Performing key generation, saving, and loading")
        # dhe_keys = DiffieHellman(18, 0) # only 10 bit keys for testing purposes
        # dhe_keys.generate_public_key()
        #
        # # Write private key to file on client.
        # # priv_key_file = open("keys/" + client_ip_addr, "wb")
        # # priv_key_file.write(bytes(str(dhe_keys.private_key, 'utf-8')))
        # # priv_key_file.close()
        #
        # # Register this client's newly created public key with the SecureIoT server.
        # register_client(ip_addr, dhe_keys.public_key)
        pub_key = crypto.get_random_bytes(16)
        priv_key = crypto.get_random_bytes(16)
        register_client(ip_addr, pub_key)

    else:
        pass
        # Read private key from existing file.
        # priv_key_file = open("keys/" + client_ip_addr, "rb")
        # priv_key = int(str(priv_key_file.readall(), 'utf-8'))
        # priv_key_file.close()

class IntegrityError(RuntimeError):
    """Error to raise whenever an integrity error is encountered."""
    pass