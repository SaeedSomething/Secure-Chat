import requests
import base64
from Crypto.PublicKey import RSA

# Generate RSA keys
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Base64 encode the public key
public_key_b64 = base64.b64encode(public_key).decode("utf-8")

# Sign up
signup_payload = {
    "username": "kimiya",
    "password": "kimiyaaa",
    "email": "kimiya@example.com",
    "ip": "127.0.0.1",
    "publickey": public_key_b64,
}
signup_response = requests.post("http://localhost:8000/signup", data=signup_payload)
print("Sign Up Response:", signup_response.text)

# Log in
login_payload = {"username": "testuser", "password": "testpassword"}
login_response = requests.post("http://localhost:8000/login", data=login_payload)
print("Login Response:", login_response.text)
