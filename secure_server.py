from pymongo import MongoClient
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from binascii import hexlify, unhexlify
import socket
from Crypto.PublicKey import RSA

# The IP and port of this server.
secure_ip, secure_port = socket.gethostbyname("localhost"), 8080

# Mongo setup
mongo_client = MongoClient(socket.gethostbyname("localhost"), 27017)
db = mongo_client['key_database']

# Register the client with IP_ADDR and their PUB KEY.
def register_client(ip_addr, pub_key):
	db.posts.insert_one({
		'ip_addr': ip_addr,
		'pub_key' : pub_key.exportKey()})

# Get the public key of IP_ADDR in STRING form.
def get_pub_key(ip_addr): # todo need to make sure this correct signature
	entry = db.posts.find_one({'ip_addr': ip_addr})
	if entry:
		return RSA.importKey(entry['pub_key'])
	return None

# Class for path handling of requests.
class RequestHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		parsed = urlparse(self.path)

		# Request path for obtaining a public key of some queried user
		# ex: localhost:8080/user_pk?q=192.168.0.1
		if parsed.path == '/user_pk':
			pub_key = get_pub_key(parsed.query[2:])
			if not pub_key is None:
				self.send_response(200, "hello")
				self.end_headers()
				return
		self.send_response(400, "Bad request...")
		self.end_headers()

# Listen for incoming HTTP requests.
def listen():
	server_address = (secure_ip, secure_port)
	httpd = HTTPServer(server_address, RequestHandler)
	try:
		print("listening on port " + str(secure_port) + " with ip " + secure_ip)
		httpd.serve_forever()
	except KeyboardInterrupt:
		pass

if __name__ == "__main__":
	listen()
