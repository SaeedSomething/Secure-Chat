import requests
import json
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

import websocket
import threading
import json
import requests

SERVER_URL = "http://localhost:8000"  # Your HTTP server URL
WS_URL = "ws://localhost:9000"  # Your WebSocket server URL

private_key = None


# Encrypt message with private key
def encrypt_with_private_key(private_key, message: str) -> str:
    encrypted = private_key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(encrypted).decode()


# Decrypt message with public key
def decrypt_with_public_key(public_key, encrypted_message: str) -> str:
    encrypted_data = base64.b64decode(encrypted_message)
    decrypted = public_key.verify(encrypted_data, padding.PKCS1v15(), hashes.SHA256())
    return decrypted.decode()


def signup():
    print("--- Sign Up ---")
    username = input("Enter username: ")
    password = input("Enter password: ")
    email = input("Enter email: ")

    # Generate RSA key pair
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(f"{username}_private.pem", "wb") as priv_file:
        priv_file.write(private_key)

    signup_payload = {
        "username": username,
        "password": password,
        "email": email,
        "ip": "127.0.0.1",
        "publickey": public_key.decode("utf-8"),
    }

    try:
        print(signup_payload)
        signup_response = requests.post(f"{SERVER_URL}/signup", data=signup_payload)
        print(signup_response)
        if signup_response.status_code == 200:

            print(f"Sign Up Response: {signup_response}")
        else:
            print(f"Sign Up Response: Error: {signup_response.text}")

    except requests.exceptions.RequestException as e:
        print(f"Sign Up Response: Error: {str(e)}")


def login():
    print("--- Login ---")
    username = input("Enter username: ")
    password = input("Enter password: ")

    login_payload = {"username": username, "password": password}

    try:
        login_response = requests.post(f"{SERVER_URL}/login", data=login_payload)

        if login_response.status_code == 200:
            response_data = login_response.json()
            server_public_key_pem = response_data["serverPublicKey"]
            server_public_key = RSA.import_key(b64decode(server_public_key_pem))
            print(f"Login successful. Server Public Key: {server_public_key_pem}")
            return username, server_public_key
        else:
            print(f"Login Response: Error: {login_response.text}")
            return None, None

    except requests.exceptions.RequestException as e:
        print(f"Login Response: Error: {str(e)}")
        return None, None


def modify_roles(username, server_public_key):
    print("--- Modify Roles ---")
    target_username = input("Enter the target username: ")
    can_create_group = input("Can create group (true/false): ")
    is_admin = input("Is admin (true/false): ")

    modify_roles_payload = {
        "requesterUsername": username,
        "targetUsername": target_username,
        "newRoles": [can_create_group.lower() == "true", is_admin.lower() == "true"],
    }

    try:
        modify_roles_response = requests.post(
            f"{SERVER_URL}/modifyRoles", json=modify_roles_payload
        )

        if modify_roles_response.status_code == 200:
            response_data = modify_roles_response.json()
            print(f"Modify Roles Response: {response_data['message']}")
        else:
            response_data = modify_roles_response.json()
            print(f"Modify Roles Response: Error: {response_data['message']}")

    except requests.exceptions.RequestException as e:
        print(f"Modify Roles Response: Error: {str(e)}")


def connect_to_user(username):
    print("--- Connect to User ---")
    target_username = input("Enter the target username: ")

    connect_payload = {
        "requesterUsername": username,
        "targetUsername": target_username,
    }

    try:
        connect_response = requests.post(
            f"{SERVER_URL}/requestChatSession", json=connect_payload
        )

        if connect_response.status_code == 200:
            # response_data = connect_response.json()
            print(f"Connect Response: {connect_response}")
        else:
            print(f"Connect Response: Error: {connect_response.text}")

    except requests.exceptions.RequestException as e:
        print(f"Connect Response: Error: {str(e)}")


def see_connections(username):
    print("--- See Connections ---")

    try:
        payload = {"username": username}
        connections_response = requests.get(
            f"{SERVER_URL}/getChatSessions", json=payload
        )

        if connections_response.status_code == 200:
            response_data = connections_response.json()
            # connections = response_data["connections"]
            if not response_data:
                print("No connections found.")
                return

            print("Connections:")
            for idx, connection in enumerate(response_data):
                print(
                    f"{idx + 1}. {connection['name']} (ID: {connection['id']} (Participants : {connection['participants']}))"
                )

            choice = int(input("Enter the connection number to connect to: ")) - 1
            if 0 <= choice < len(response_data):
                connection_id = response_data[choice]["id"]
                chat(username, connection_id)
            else:
                print("Invalid choice.")
        else:
            print(f"See Connections Response: Error: {connections_response.text}")

    except requests.exceptions.RequestException as e:
        print(f"See Connections Response: Error: {str(e)}")
    except json.JSONDecodeError as e:
        print(f"See Connections Response: Error: {str(e)}")


def on_message(ws, message):
    print(message)


def on_error(ws, error):
    print(f"WebSocket Error: {error}")


def on_close(ws):
    print("WebSocket connection closed")


def on_open(ws, username, connection_id):
    def run(*args):
        chat_payload = {
            "username": username,
            "connectionId": connection_id,
            "message": "join",
            "type": "join",
        }
        ws.send(json.dumps(chat_payload))
        while True:
            message = input("Enter message (or 'exit' to exit): ")
            if message.lower() == "exit":
                ws.close()
                break

            chat_payload = {
                "username": username,
                "connectionId": connection_id,
                "message": message,
                "type": "chat",
            }
            ws.send(json.dumps(chat_payload))

    threading.Thread(target=run).start()


def chat(username, connection_id):
    print(f"--- Chat with Connection ID: {connection_id} ---")

    ws = websocket.WebSocketApp(
        WS_URL, on_message=on_message, on_error=on_error, on_close=on_close
    )
    ws.on_open = lambda ws: on_open(ws, username, connection_id)
    ws.run_forever()


def main():
    print("Welcome to Secure Messaging App")

    username = None
    server_public_key = None

    while True:
        print("\nOptions:")
        if username:
            print("1. Modify Roles")
            print("2. Connect to User")
            print("3. See Connections")
            print("4. Log Out")
        else:
            print("1. Sign Up")
            print("2. Log In")
        print("5. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            if username:
                modify_roles(username, server_public_key)
            else:
                signup()
        elif choice == "2":
            if username:
                connect_to_user(username)
            else:
                username, server_public_key = login()
                if username:
                    print(f"Logged in as {username}")
        elif choice == "3" and username:
            see_connections(username)
        elif choice == "4" and username:
            username = None
            server_public_key = None
            print("Logged out.")
        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
