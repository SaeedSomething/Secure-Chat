import requests
import json
import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

SERVER_URL = "http://localhost:8000"


def signup():
    print("--- Sign Up ---")
    username = input("Enter username: ")
    password = input("Enter password: ")
    email = input("Enter email: ")

    signup_payload = {
        "username": username,
        "password": password,
        "email": email,
    }

    try:
        signup_response = requests.post(f"{SERVER_URL}/signup", json=signup_payload)

        if signup_response.status_code == 200:
            response_data = signup_response.json()
            print(f"Sign Up Response: {response_data['message']}")
        else:
            print(f"Sign Up Response: Error: {signup_response.text}")

    except requests.exceptions.RequestException as e:
        print(f"Sign Up Response: Error: {str(e)}")
    except ValueError:
        print(
            f"Sign Up Response: Error: Unexpected response format: {signup_response.text}"
        )


def login():
    print("--- Login ---")
    username = input("Enter username: ")
    password = input("Enter password: ")

    login_payload = {"username": username, "password": password}

    try:
        login_response = requests.post(f"{SERVER_URL}/login", json=login_payload)

        if login_response.status_code == 200:
            response_data = login_response.json()
            server_public_key_pem = response_data["serverPublicKey"]
            server_public_key = RSA.import_key(server_public_key_pem)
            print(f"Login successful. Server Public Key: {server_public_key_pem}")
            return username, server_public_key
        else:
            print(f"Login Response: {login_response.text}")
            return None, None

    except requests.exceptions.RequestException as e:
        print(f"Login Response: Error: {str(e)}")
        return None, None
    except ValueError:
        print("Login Response: Error: Unexpected response format.")
        return None, None


def connect_to_user(my_username, recipient_username, server_public_key):
    print("--- Connect to User ---")
    try:
        response = requests.get(f"{SERVER_URL}/get_public_key/{recipient_username}")

        if response.status_code == 200:
            signed_data = response.json()
            signature = b64decode(signed_data["signature"])
            public_key_pem = signed_data["publicKey"]

            # Verify the signature
            verifier = PKCS1_OAEP.new(server_public_key)
            if verifier.decrypt(signature) == public_key_pem.encode():
                recipient_public_key = RSA.import_key(public_key_pem)
                print(
                    f"Connected to {recipient_username}. Received Public Key: {public_key_pem}"
                )
                return recipient_public_key
            else:
                print("Failed to verify server's signature.")
                return None
        else:
            print(f"Failed to get recipient's public key: {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Error: {str(e)}")
        return None


def encrypt_message(recipient_public_key, message):
    cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
    encrypted_message = cipher_rsa.encrypt(message.encode())
    return b64encode(encrypted_message).decode()


def decrypt_message(private_key, encrypted_message):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(b64decode(encrypted_message))
    return decrypted_message.decode()


def send_message(my_username, recipient_username, recipient_public_key):
    while True:
        message = input("Enter message: ")
        encrypted_message = encrypt_message(recipient_public_key, message)
        print(f"Encrypted Message: {encrypted_message}")

        # Simulate sending message (in real case, use WebSocket)
        print(f"Sending to {recipient_username}: {encrypted_message}")


def receive_message(private_key):
    while True:
        encrypted_message = input("Enter received encrypted message: ")
        message = decrypt_message(private_key, encrypted_message)
        print(f"Decrypted Message: {message}")


def main():
    print("Welcome to Secure Messaging App")

    username = None
    server_public_key = None
    recipient_public_key = None

    while True:
        print("\nOptions:")
        print("1. Login")
        print("2. Sign Up")
        print("3. Connect to User")
        print("4. Send Message")
        print("5. Receive Message")
        print("6. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            username, server_public_key = login()
            if username:
                print(f"Logged in as {username}")
            else:
                print("Login failed. Try again.")

        elif choice == "2":
            signup()

        elif choice == "3":
            if not username:
                print("Please login first.")
                continue
            recipient_username = input("Enter username of user to connect to: ")
            recipient_public_key = connect_to_user(
                username, recipient_username, server_public_key
            )
            if recipient_public_key:
                print(f"Connected to {recipient_username}")

        elif choice == "4":
            if not username:
                print("Please login first.")
                continue
            if not recipient_public_key:
                print("Please connect to a user first.")
                continue
            send_message(username, recipient_username, recipient_public_key)

        elif choice == "5":
            if not username:
                print("Please login first.")
                continue
            receive_message(RSA.import_key(open(f"{username}_private.pem").read()))

        elif choice == "6":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
