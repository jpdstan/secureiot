# SecureIoT: Security as a service

## Description

A test client and server is used to demonstrate the usage of the API and SecureIoT application server.

## Files

`secure_api.py` the actual API a user would import into their Python project
* `init(ip_addr)`: Registers IP_ADDR with the application server. Must be done on all devices upon starting. Currently, all this does is create the public/private keypair and write the private key to the machine.
* `send_message(msg, user, port)`: Sends a message to USER (an IP address) on PORT. This is what the test client will use to encrypt and send the humidity to the test server.
* `receive_message(msg, user)`: Takes MSG and the shared_secret with USER to decrypt MSG. This will be used by the test server.
`secure_server.py` runs on our backend to continuously serve all requests
`test_client.py` simple client using the API, reporting the humidity to the server
`test_server.py` simple server using the API, calculating a continuous average of the humidity from all clients
`crypto.py` library for standard encryption/decryption mechanisms (not proprietary)