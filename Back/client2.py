import requests
import json
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

SERVER_URL = "http://localhost:8000"


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

        if signup_response.status_code == 200:
            response_data = signup_response.json()
            print(f"Sign Up Response: {response_data['message']}")
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
            response_data = connect_response.json()
            print(f"Connect Response: {response_data['message']}")
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
                print(f"{idx + 1}. {connection['name']} (ID: {connection['id']})")

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


def chat(username, connection_id):
    print(f"--- Chat with Connection ID: {connection_id} ---")

    while True:
        message = input("Enter message (or 'exit' to exit): ")
        if message.lower() == "exit":
            break

        chat_payload = {
            "username": username,
            "connectionId": connection_id,
            "message": message,
        }

        try:
            chat_response = requests.post(
                f"{SERVER_URL}/sendMessage", data=chat_payload
            )

            if chat_response.status_code == 200:
                print("Message sent successfully.")
            else:
                print(f"Send Message Response: Error: {chat_response.text}")

        except requests.exceptions.RequestException as e:
            print(f"Send Message Response: Error: {str(e)}")

        # Fetch incoming messages
        try:
            messages_response = requests.get(
                f"{SERVER_URL}/getMessages/{connection_id}"
            )

            if messages_response.status_code == 200:
                response_data = messages_response.json()
                messages = response_data["messages"]
                print("--- Incoming Messages ---")
                for msg in messages:
                    print(f"{msg['sender']}: {msg['content']}")
            else:
                print(f"Get Messages Response: Error: {messages_response.text}")

        except requests.exceptions.RequestException as e:
            print(f"Get Messages Response: Error: {str(e)}")
        except json.JSONDecodeError as e:
            print(f"Get Messages Response: Error: {str(e)}")


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
