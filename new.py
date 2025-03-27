import os
import time
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from cryptography.fernet import Fernet
import binascii
import re

class SecureFileManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Management System")
        self.root.geometry("900x600")

        # Security Setup
        self.key = self.load_or_generate_key()
        self.cipher = Fernet(self.key)
        self.logged_in = False
        self.current_user = None

        # UI Setup
        self.setup_ui()

    def setup_ui(self):
        """Initialize all UI components"""
        self.root.configure(bg="#f5f5f5")

        # Header
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=10, pady=10)

        title_label = ttk.Label(header_frame, text="Secure File Manager", font=('Helvetica', 18, 'bold'))
        title_label.pack(side=tk.LEFT)

        self.auth_status = ttk.Label(header_frame, text="Not Logged In", font=('Helvetica', 10), foreground="red")
        self.auth_status.pack(side=tk.RIGHT)

        # Main Frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Left Panel (File Operations)
        left_panel = ttk.Frame(main_frame, width=200)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5)

        ttk.Label(left_panel, text="File Operations", font=('Helvetica', 12, 'bold')).pack(pady=5)

        operations = [
            ("📁 Open File", self.open_file),
            ("💾 Save File", self.save_file),
            ("🔒 Encrypt File", self.encrypt_file),
            ("🔓 Decrypt File", self.decrypt_file)
        ]

        for text, cmd in operations:
            btn = ttk.Button(left_panel, text=text, command=cmd)
            btn.pack(fill=tk.X, pady=3)

        # Right Panel (File Content and Logs)
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # File Content Viewer
        self.file_content = scrolledtext.ScrolledText(right_panel, wrap=tk.WORD, width=60, height=20)
        self.file_content.pack(fill=tk.BOTH, expand=True, pady=5)

        # Security Log
        log_frame = ttk.LabelFrame(right_panel, text="Security Log", padding=10)
        log_frame.pack(fill=tk.BOTH, pady=5)

        self.security_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=60, height=8, bg='#f0f0f0')
        self.security_log.pack(fill=tk.BOTH)
        self.security_log.config(state=tk.DISABLED)

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, padx=1, pady=1)

        # Login Dialog
        self.show_login_dialog()

    def show_login_dialog(self):
        """Show login window"""
        login_window = tk.Toplevel(self.root)
        login_window.title("Login Required")
        login_window.geometry("300x250")
        login_window.grab_set()

        ttk.Label(login_window, text="Secure Login", font=('Helvetica', 14)).pack(pady=10)

        ttk.Label(login_window, text="Username:").pack()
        self.username_entry = ttk.Entry(login_window)
        self.username_entry.pack(pady=5)

        ttk.Label(login_window, text="Password:").pack()
        self.password_entry = ttk.Entry(login_window, show="*")
        self.password_entry.pack(pady=5)

        ttk.Button(login_window, text="Login", command=lambda: self.authenticate_user(login_window)).pack(pady=15)

    def authenticate_user(self, window):
        """Authenticate user"""
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username == "admin" and password == "password":  # Change this for real authentication
            self.logged_in = True
            self.current_user = username
            self.auth_status.config(text=f"Logged in as {username}", foreground="green")
            self.log_security_event(f"User {username} logged in successfully")
            window.destroy()
        else:
            messagebox.showerror("Error", "Invalid credentials")
            self.log_security_event("Failed login attempt", warning=True)

    def log_security_event(self, message, warning=False):
        """Log security events"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] {message}\n"

        self.security_log.config(state=tk.NORMAL)
        self.security_log.insert(tk.END, log_msg)
        self.security_log.config(state=tk.DISABLED)
        self.security_log.see(tk.END)

    def load_or_generate_key(self):
        """Load encryption key or generate new one"""
        key_file = "secret.key"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(key)
            return key

    def open_file(self):
        """Open and read a file"""
        if not self.logged_in:
            messagebox.showerror("Error", "Please login first!")
            return

        filepath = filedialog.askopenfilename()
        if filepath:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                self.file_content.delete(1.0, tk.END)
                self.file_content.insert(tk.END, content)
                self.status_var.set(f"Opened: {os.path.basename(filepath)}")
                self.log_security_event(f"Opened file: {filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open file: {str(e)}")

    def save_file(self):
        """Save the file content"""
        if not self.logged_in:
            messagebox.showerror("Error", "Please login first!")
            return

        filepath = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("Text Files", "*.txt"),
                                                           ("All Files", "*.*")])
        if filepath:
            try:
                content = self.file_content.get(1.0, tk.END)
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)
                self.status_var.set(f"Saved: {os.path.basename(filepath)}")
                self.log_security_event(f"Saved file: {filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")

    def encrypt_file(self):
        """Encrypt file content"""
        if not self.logged_in:
            messagebox.showerror("Error", "Please login first!")
            return

        content = self.file_content.get(1.0, tk.END).encode()
        encrypted = self.cipher.encrypt(content)
        self.file_content.delete(1.0, tk.END)
        self.file_content.insert(tk.END, encrypted.decode('latin-1'))
        self.log_security_event("File content encrypted")

    def decrypt_file(self):
        """Decrypt file content"""
        if not self.logged_in:
            messagebox.showerror("Error", "Please login first!")
            return

        content = self.file_content.get(1.0, tk.END).encode('latin-1')
        decrypted = self.cipher.decrypt(content)
        self.file_content.delete(1.0, tk.END)
        self.file_content.insert(tk.END, decrypted.decode())
        self.log_security_event("File content decrypted")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureFileManager(root)
    root.mainloop()