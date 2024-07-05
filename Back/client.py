import requests
import base64
from Crypto.PublicKey import RSA

SERVER_URL = "http://localhost:8000"


def main():
    username, private_key = login()
    print(f"Logged in as {username}")
    menu(username, private_key)


def login():
    print("--- Login ---")
    username = input("Enter username: ")
    password = input("Enter password: ")

    login_payload = {
        "username": username,
        "password": password,
    }

    login_response = requests.post(f"{SERVER_URL}/login", data=login_payload)
    print("Login Response:", login_response.text)

    if login_response.status_code == 200:
        response_data = login_response.json()
        server_public_key_pem = decode_and_import_server_public_key(
            response_data["serverPublicKey"]
        )
        return username, server_public_key_pem
    else:
        print("Login failed.")
        return None, None


def decode_and_import_server_public_key(server_public_key_base64):
    try:
        # Decode Base64
        server_public_key_bytes = base64.b64decode(server_public_key_base64)
        # Import as RSA key
        server_public_key = RSA.import_key(server_public_key_bytes)
        return server_public_key
    except ValueError as e:
        print(f"Error decoding or importing server's public key: {e}")
        return None


def menu(username, private_key):
    while True:
        print("--- Menu ---")
        print("1. Connect to user")
        print("2. Send message")
        print("3. Accept incoming messages")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            connect_to_user(username, private_key)
        elif choice == "2":
            send_message(username, private_key)
        elif choice == "3":
            accept_incoming_messages(username, private_key)
        elif choice == "4":
            break
        else:
            print("Invalid choice. Please enter a valid option.")


def connect_to_user(username, private_key):
    print("--- Connect to User ---")
    recipient_username = input("Enter username of user to connect to: ")

    # Request server for recipient's public key
    request_payload = {
        "username": recipient_username,
    }
    response = requests.post(f"{SERVER_URL}/get_public_key", data=request_payload)
    if response.status_code == 200:
        recipient_public_key_pem = response.text
        recipient_public_key = RSA.import_key(recipient_public_key_pem)
        print(f"Received recipient's public key: {recipient_public_key}")

        # Now send and receive encrypted messages using recipient_public_key and private_key
        # Implement message sending/receiving logic here

    else:
        print(f"Failed to get recipient's public key: {response.text}")


def send_message(username, private_key):
    print("--- Send Message ---")
    recipient_username = input("Enter username of user to send message to: ")
    message = input("Enter message: ")

    # Encrypt message with recipient's public key
    # encrypted_message = encrypt_message(message, recipient_public_key)

    # Send encrypted message to recipient
    # Implement WebSocket or HTTP POST logic here


def accept_incoming_messages(username, private_key):
    print("--- Accept Incoming Messages ---")
    # Implement logic to listen for incoming messages using WebSocket


if __name__ == "__main__":
    main()
