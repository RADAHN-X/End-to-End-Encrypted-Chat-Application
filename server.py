import socket
import threading
import json
import sqlite3
import hashlib
import os
from datetime import datetime

HOST = '127.0.0.1'
PORT = 9090

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

DATABASE_FILE = "chat_server.db"

clients = {}
public_keys = {}


def init_database():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    conn.commit()
    conn.close()


def hash_password(password):
    """تجزئة كلمة المرور باستخدام SHA-256"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def register_user(username, password):
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return {"status": "error", "message": "Username already exists"}

        password_hash = hash_password(password)
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )

        conn.commit()
        conn.close()
        return {"status": "success", "message": "Registration successful"}

    except Exception as e:
        return {"status": "error", "message": str(e)}


def authenticate_user(username, password):
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)
        )
        result = cursor.fetchone()
        conn.close()

        if result:
            stored_hash = result[0]
            input_hash = hash_password(password)
            if stored_hash == input_hash:
                return {"status": "success", "message": "Authentication successful"}

        return {"status": "error", "message": "Invalid username or password"}

    except Exception as e:
        return {"status": "error", "message": str(e)}


def broadcast(message, _sender_socket=None):
    for username, client_socket in clients.items():
        if client_socket != _sender_socket:
            try:
                client_socket.send(json.dumps(message).encode('utf-8'))
            except:
                cleanup_client(username)


def cleanup_client(username):
    """تنظيف بيانات client عند انقطاع الاتصال"""
    print(f"Cleaning up disconnected client: {username}")
    if username in clients:
        clients.pop(username)
    if username in public_keys:
        public_keys.pop(username)

    disconnect_message = {
        "type": "user_left",
        "username": username
    }
    broadcast(disconnect_message)


def handle_client(client_socket):
    username = None
    try:
        auth_data = json.loads(client_socket.recv(4096).decode('utf-8'))
        action = auth_data.get('action')

        if action == 'register':
            response = register_user(
                auth_data['username'],
                auth_data['password']
            )
            client_socket.send(json.dumps(response).encode('utf-8'))

            if response['status'] == 'error':
                client_socket.close()
                return

        elif action == 'login':
            response = authenticate_user(
                auth_data['username'],
                auth_data['password']
            )
            client_socket.send(json.dumps(response).encode('utf-8'))

            if response['status'] == 'error':
                client_socket.close()
                return
        else:
            client_socket.send(json.dumps({
                "status": "error",
                "message": "Invalid action"
            }).encode('utf-8'))
            client_socket.close()
            return

        username = auth_data['username']
        public_key = auth_data['public_key']

        if username in clients:
            client_socket.send(json.dumps({
                "status": "error",
                "message": "User already logged in from another device"
            }).encode('utf-8'))
            client_socket.close()
            return

        clients[username] = client_socket
        public_keys[username] = public_key

        print(f"Connected with {username} at {client_socket.getpeername()}")

        initial_payload = {
            "type": "all_users",
            "users": {user: key for user, key in public_keys.items() if user != username}
        }
        client_socket.send(json.dumps(initial_payload).encode('utf-8'))

        new_user_notification = {
            "type": "new_user",
            "username": username,
            "public_key": public_key
        }
        broadcast(new_user_notification, _sender_socket=client_socket)

        while True:
            encrypted_message_json = client_socket.recv(4096).decode('utf-8')
            if not encrypted_message_json:
                break

            encrypted_message = json.loads(encrypted_message_json)
            recipient = encrypted_message['recipient']
            payload = encrypted_message['payload']

            print(f"Relaying encrypted message from {username} to {recipient}...")
            if recipient in clients:
                recipient_socket = clients[recipient]
                payload['sender'] = username
                recipient_socket.send(json.dumps({
                    "type": "encrypted_message",
                    "payload": payload
                }).encode('utf-8'))

    except (ConnectionResetError, json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"Client {username or 'unknown'} disconnected: {e}")
    except Exception as e:
        print(f"Error with client {username}: {e}")
    finally:
        if username and username in clients:
            cleanup_client(username)
        client_socket.close()


def start_server():
    init_database()
    print("Server is listening on port 9090...")
    while True:
        client_socket, address = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()


if __name__ == "__main__":
    start_server()
