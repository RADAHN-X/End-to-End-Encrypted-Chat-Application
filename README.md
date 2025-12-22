Secure-Chat-App
A simple, end-to-end encrypted chat application built with Python. This project uses a client-server architecture and leverages the cryptography library to ensure that messages are secure and private.

🌟 Features
End-to-End Encryption (E2EE): Messages are encrypted on the sender's device and can only be decrypted by the recipient. The server only relays encrypted data and cannot read the message content.

Client-Server Architecture: A central server that relays messages to multiple clients.

Graphical User Interface (GUI): A user-friendly interface built with Python's built-in tkinter library.

Dynamic Session Key Generation: A unique symmetric session key is generated for each chat session and securely distributed to all clients using hybrid encryption.

🛠️ How It Works
The application employs a hybrid encryption model to ensure both security and efficiency:

Asymmetric Encryption (RSA):

When a client connects, it generates a public/private RSA key pair.

The client's public key is sent to the server.

Symmetric Encryption (Fernet):

Once at least two clients are connected, the server generates a strong, single-use symmetric session key.

The server encrypts this session key using each client's respective public key.

Each client receives the encrypted session key and decrypts it using their own private key.

Secure Communication:

All subsequent chat messages are encrypted and decrypted by the clients using the shared, symmetric session key. This is much faster than using asymmetric encryption for every message.

This ensures that only the intended recipients (the clients in the chat) can read the messages. The server, and any potential eavesdroppers, cannot decipher the content.

Prerequisites
Python 3.x

The cryptography library

⚙️ Installation
Clone the repository:


Install the required library:
Open your terminal or command prompt and run the following command to install cryptography:

bash
pip install cryptography
🚀 How to Run
You need to run the server first, and then you can run as many clients as you like.

Start the Server:
Open a terminal and run the server.py script. The server will start listening for incoming connections.

bash
python server.py
You will see the message: Server is listening...

Start a Client:
Open a new terminal window and run the client.py script.

bash
python client.py
A small window will pop up asking for a nickname. Enter a nickname and press OK. The chat window will appear.

Start More Clients:
Repeat Step 2 to open more chat windows. Each client should have a unique nickname.

Start Chatting!

Once the second client connects, the server will securely distribute the session key, and you'll see a "Secure session started" message in the chat windows.

Now, any message you send from one client will appear in all other clients' chat windows, fully encrypted.

🔮 Future Improvements
This is a foundational project with many opportunities for enhancement:

Improved GUI: Use a more modern GUI library like customtkinter or PyQt for a better look and feel.

Online User List: Display a list of currently connected users in the client GUI.

Private Messaging: Implement a feature to allow one-to-one private conversations.

Persistent Chat History: Add an option to save chat logs locally.

Containerization: Use Docker to easily package and deploy the server.
