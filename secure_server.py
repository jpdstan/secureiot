import socket
from pymongo import MongoClient
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

host, port = "127.0.0.1", 8080

# Caches users (MAC addresses) and their public keys in memory to minimize DB queries.
cached_users = {}

mongo_client = MongoClient('localhost', 27017)
db = mongo_client['key_database']

# Register the client with MAC_ADDR and their PUB KEY.
def register_client(mac_addr, pub_key):
	print("Registering " + mac_addr + " with " + pub_key)
	db.posts.insert_one({
		'mac_addr': mac_addr,
		'pub_key' : pub_key})
	
	# results = db.posts.find()

	# for result in results:
	# 	print(result)

# Get the public key of MAC_ADDR.
def get_pub_key(mac_addr):
	entry = db.posts.find_one({'mac_addr': mac_addr})
	if entry:
		print(entry)
		return entry['pub_key']
	return None

class RequestHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		parsed = urlparse(self.path)
		if parsed.path == '/user_pk':
			pub_key = get_pub_key(parsed.query)
			if not pub_key is None:
				self.send_response(200, pub_key)
		self.send_response(400)

# Listen for incoming HTTP requests.
def listen():
	server_address = (host, port)
	httpd = HTTPServer(server_address, RequestHandler)
	try:
		print("listening on port " + str(port) + " with ip " + host)
		httpd.serve_forever()
	except KeyboardInterrupt:
		pass


if __name__ == "__main__":
	# results = db.posts.find()
	# for result in results:
	# 	print(result)
	listen()
