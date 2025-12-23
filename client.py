import socket
import threading
import json
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox, PanedWindow, Listbox, Frame, Entry, Button, END, LEFT, \
    RIGHT, BOTH, X, Y, StringVar, Label, Toplevel, ttk, BOTTOM
from tkinter import font as tkfont

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

HOST = '127.0.0.1'
PORT = 9090


class LoginWindow:
    def __init__(self, master):
        self.master = master
        master.title("Secure Chat - Login")
        master.geometry("400x400")
        master.resizable(False, False)

        title_font = tkfont.Font(family="Arial", size=16, weight="bold")
        label_font = tkfont.Font(family="Arial", size=11)
        button_font = tkfont.Font(family="Arial", size=11, weight="bold")

        Label(master, text="🔐 Secure Chat", font=title_font, fg="#2E86AB").pack(pady=30)

        form_frame = Frame(master)
        form_frame.pack(pady=20, padx=40, fill=X)

        Label(form_frame, text="Username:", font=label_font).pack(anchor='w', pady=(0, 5))
        self.username_entry = Entry(form_frame, font=("Arial", 11))
        self.username_entry.pack(fill=X, ipady=8, pady=(0, 15))
        self.username_entry.bind("<Return>", lambda e: self.password_entry.focus())

        Label(form_frame, text="Password:", font=label_font).pack(anchor='w', pady=(0, 5))
        self.password_entry = Entry(form_frame, show="•", font=("Arial", 11))
        self.password_entry.pack(fill=X, ipady=8, pady=(0, 20))
        self.password_entry.bind("<Return>", lambda e: self.login())

        button_frame = Frame(form_frame)
        button_frame.pack(fill=X)

        self.login_button = Button(
            button_frame,
            text="Login",
            command=self.login,
            bg="#2E86AB",
            fg="white",
            font=button_font,
            padx=20,
            pady=10
        )
        self.login_button.pack(side=LEFT, padx=(0, 10))

        self.register_button = Button(
            button_frame,
            text="Register",
            command=self.register,
            bg="#73AB84",
            fg="white",
            font=button_font,
            padx=20,
            pady=10
        )
        self.register_button.pack(side=LEFT)

        self.status_label = Label(master, text="", fg="gray")
        self.status_label.pack(pady=10)

        self.logged_in = False
        self.username = None
        self.public_key = None

        self.connect_to_server()

        self.username_entry.focus()

    def connect_to_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))
            self.update_status("Connected to server", "green")
        except ConnectionRefusedError:
            self.update_status("Cannot connect to server", "red")
            self.disable_buttons()

    def update_status(self, text, color="gray"):
        self.status_label.config(text=text, fg=color)

    def disable_buttons(self):
        self.login_button.config(state="disabled")
        self.register_button.config(state="disabled")

    def enable_buttons(self):
        self.login_button.config(state="normal")
        self.register_button.config(state="normal")

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showwarning("Input Error", "Please enter both username and password")
            return

        self.send_auth_request('login', username, password)

    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showwarning("Input Error", "Please enter both username and password")
            return

        if len(password) < 6:
            messagebox.showwarning("Password Error", "Password must be at least 6 characters")
            return

        confirm = simpledialog.askstring("Confirm Password",
                                         "Please confirm your password:",
                                         show="•",
                                         parent=self.master)
        if confirm != password:
            messagebox.showerror("Password Mismatch", "Passwords do not match")
            return

        self.send_auth_request('register', username, password)

    def send_auth_request(self, action, username, password):
        try:
            key = RSA.generate(2048)
            self.public_key = key.publickey().export_key().decode('utf-8')
            self.private_key = key.export_key()

            auth_payload = {
                'action': action,
                'username': username,
                'password': password,
                'public_key': self.public_key
            }

            self.sock.send(json.dumps(auth_payload).encode('utf-8'))

            response_json = self.sock.recv(4096).decode('utf-8')
            response = json.loads(response_json)

            if response['status'] == 'success':
                self.username = username
                self.logged_in = True
                self.open_chat_window()
            else:
                messagebox.showerror("Authentication Failed", response['message'])

        except Exception as e:
            messagebox.showerror("Connection Error", f"Error: {str(e)}")

    def open_chat_window(self):
        self.master.withdraw()

        chat_window = Toplevel(self.master)
        chat_app = ChatClientGUI(chat_window, self.sock, self.username, self.private_key, self.public_key)

        def on_chat_close():
            try:
                self.sock.close()
            except:
                pass
            self.master.destroy()

        chat_window.protocol("WM_DELETE_WINDOW", on_chat_close)


class ChatClientGUI:
    def __init__(self, master, sock, username, private_key, public_key):
        self.master = master
        self.sock = sock
        self.username = username
        self.private_key = private_key
        self.public_key = public_key

        master.title(f"Secure Chat - {username}")
        master.geometry("800x600")

        self.public_keys = {}
        self.running = True

        self.paned_window = PanedWindow(master, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        self.paned_window.pack(fill=BOTH, expand=1)

        users_frame = Frame(self.paned_window, width=200)
        users_frame.pack_propagate(False)

        header_frame = Frame(users_frame, bg="#2E86AB", height=40)
        header_frame.pack_propagate(False)
        header_frame.pack(fill=X)

        Label(header_frame, text="👥 Online Users",
              font=("Arial", 12, "bold"),
              bg="#2E86AB",
              fg="white").pack(pady=10)

        tk.Label(users_frame, text="", font=("Arial", 12)).pack(pady=5)
        self.users_listbox = Listbox(users_frame, font=("Arial", 11), selectbackground="#2E86AB")
        self.users_listbox.pack(fill=BOTH, expand=1, padx=5, pady=5)

        user_info_frame = Frame(users_frame, bg="#f0f0f0", height=50)
        user_info_frame.pack_propagate(False)
        user_info_frame.pack(fill=X, side=BOTTOM)
        Label(user_info_frame, text=f"Logged in as:",
              font=("Arial", 9), bg="#f0f0f0").pack(pady=(5, 0))
        Label(user_info_frame, text=f"{username}",
              font=("Arial", 10, "bold"),
              fg="#2E86AB", bg="#f0f0f0").pack()

        self.paned_window.add(users_frame, width=200)

        chat_frame = Frame(self.paned_window)
        chat_frame.pack_propagate(False)

        self.text_area = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            state='disabled',
            font=("Arial", 11),
            bg="#f9f9f9"
        )
        self.text_area.pack(padx=10, pady=10, fill=BOTH, expand=1)

        input_frame = Frame(chat_frame, bg="white")
        input_frame.pack(fill=X, padx=10, pady=5)

        self.input_area = Entry(
            input_frame,
            font=("Arial", 11),
            relief=tk.FLAT,
            bg="#f5f5f5"
        )
        self.input_area.pack(side=LEFT, fill=X, expand=True, ipady=8, padx=(5, 5))
        self.input_area.bind("<Return>", self.send_message_event)
        self.input_area.focus()

        self.send_button = Button(
            input_frame,
            text="Send",
            command=self.send_message_event,
            font=("Arial", 10, "bold"),
            bg="#2E86AB",
            fg="white",
            padx=20
        )
        self.send_button.pack(side=RIGHT)

        self.paned_window.add(chat_frame)

        receive_thread = threading.Thread(target=self.receive_loop, daemon=True)
        receive_thread.start()

        master.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.display_system_message("Welcome to Secure Chat! Select a user to start chatting.")

    def receive_loop(self):
        while self.running:
            try:
                message_json = self.sock.recv(4096).decode('utf-8')
                if not message_json:
                    break
                message = json.loads(message_json)
                self.handle_server_message(message)
            except (ConnectionResetError, json.JSONDecodeError):
                if self.running:
                    self.display_system_message("❌ Connection to the server was lost.")
                break
            except Exception as e:
                if self.running:
                    print(f"Receive loop error: {e}")
                break

    def handle_server_message(self, message):
        msg_type = message.get('type')
        if msg_type == 'all_users':
            self.public_keys = {user: RSA.import_key(key_str) for user, key_str in message['users'].items()}
            self.update_user_list()
            self.display_system_message("✅ Successfully connected to the chat.")
        elif msg_type == 'new_user':
            username = message['username']
            if username != self.username:
                self.public_keys[username] = RSA.import_key(message['public_key'])
                self.update_user_list()
                self.display_system_message(f"--- {username} has joined the chat. ---")
        elif msg_type == 'user_left':
            username = message['username']
            if username in self.public_keys:
                del self.public_keys[username]
                self.update_user_list()
                self.display_system_message(f"--- {username} has left the chat. ---")
        elif msg_type == 'encrypted_message':
            self.decrypt_and_display_message(message)

    def update_user_list(self):
        self.users_listbox.delete(0, END)
        for user in sorted(self.public_keys.keys()):
            if user != self.username:
                self.users_listbox.insert(END, f"👤 {user}")

    def decrypt_and_display_message(self, message):
        try:
            payload = message['payload']
            sender = payload['sender']

            encrypted_session_key = base64.b64decode(payload['session_key'])
            nonce = base64.b64decode(payload['nonce'])
            tag = base64.b64decode(payload['tag'])
            ciphertext = base64.b64decode(payload['ciphertext'])

            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.private_key))
            session_key = cipher_rsa.decrypt(encrypted_session_key)

            cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
            decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag).decode('utf-8')

            self.display_message(f"[{sender}]: {decrypted_message}")
        except Exception as e:
            self.display_system_message(f"⚠️ Failed to decrypt a message: {e}")

    def send_message_event(self, event=None):
        message = self.input_area.get().strip()
        if not message:
            return

        selected_indices = self.users_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("No Recipient", "Please select a user from the list to send a message to.")
            return
        recipient = self.users_listbox.get(selected_indices[0]).replace("👤 ", "")

        if recipient not in self.public_keys:
            messagebox.showwarning("User Offline", f"{recipient} is no longer online.")
            self.update_user_list()
            return

        self.display_message(f"[You to {recipient}]: {message}")
        self.input_area.delete(0, END)

        try:
            recipient_public_key = self.public_keys[recipient]
            session_key = get_random_bytes(16)
            cipher_aes = AES.new(session_key, AES.MODE_GCM)
            ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))

            cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
            encrypted_session_key = cipher_rsa.encrypt(session_key)

            payload_to_send = {
                'session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
                'nonce': base64.b64encode(cipher_aes.nonce).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
            }
            final_message = {'recipient': recipient, 'payload': payload_to_send}
            self.sock.send(json.dumps(final_message).encode('utf-8'))
        except Exception as e:
            self.display_system_message(f"❌ Could not send message: {e}")

    def display_message(self, message):
        self.text_area.config(state='normal')
        self.text_area.insert(END, message + "\n")
        self.text_area.yview(END)
        self.text_area.config(state='disabled')

    def display_system_message(self, message):
        """عرض رسالة نظام (مثل دخول/خروج مستخدم) بلون مختلف"""
        self.text_area.config(state='normal')
        self.text_area.insert(END, message + "\n", "system")
        self.text_area.tag_config("system", foreground="gray", font=("Arial", 10, "italic"))
        self.text_area.yview(END)
        self.text_area.config(state='disabled')

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.running = False
            if hasattr(self, 'sock'):
                self.sock.close()
            self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    login_app = LoginWindow(root)
    root.mainloop()
