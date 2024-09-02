import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ttkbootstrap as tb
from account_manager import AccountManager
from encryption_manager import EncryptionManager
from login_manager import LoginManager
import threading
import pyperclip
import os

class GUIManager:
    def __init__(self):
        self.account_manager = AccountManager()

        self.root = tb.Window(themename="darkly")
        self.root.title("Info Encryptor")

        # Configure resizing behavior for the main window
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        self.user_label = None  # Reference to the user label

        self.show_login_screen()

        self.root.mainloop()

    def show_login_screen(self):
        self.login_frame = ttk.Frame(self.root)
        self.login_frame.pack(pady=20)

        ttk.Label(self.login_frame, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(self.login_frame, width=40)
        self.username_entry.pack(pady=5)

        ttk.Label(self.login_frame, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(self.login_frame, width=40, show='*')
        self.password_entry.pack(pady=5)

        ttk.Button(self.login_frame, text="Login", command=self.login_user, width=30).pack(pady=10)
        ttk.Button(self.login_frame, text="Create Account", command=self.create_account, width=30).pack(pady=10)

    def login_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        try:
            self.account_manager.login(username, password)
            self.user_folder = self.account_manager.get_user_folder()
            self.encryption_manager = EncryptionManager(self.user_folder, self.account_manager.master_key)
            self.login_manager = LoginManager(self.user_folder, self.encryption_manager)

            self.login_frame.pack_forget()
            self.show_main_interface()

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def create_account(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        try:
            self.account_manager.create_account(username, password)
            messagebox.showinfo("Success", "Account created successfully. Please log in.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_main_interface(self):
        # Display the logged-in user at the top
        if self.user_label is None:
            self.user_label = ttk.Label(self.root, text=f"Logged in as: {self.account_manager.current_user.title()}", foreground="green", font=("Helvetica", 10))
            self.user_label.grid(row = 0, column=0, padx=10, pady=10)
        else:
            self.user_label.config(text=f"Logged in as: {self.account_manager.current_user.title()}")
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=10)

        # Configure resizing behavior for notebook tabs
        self.root.rowconfigure(0, weight=0)
        self.root.rowconfigure(1, weight=1)
        self.root.columnconfigure(0, weight=1)

        self.setup_encrypt_decrypt_tab()
        self.setup_login_data_tab()

    def setup_encrypt_decrypt_tab(self):
        encrypt_decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(encrypt_decrypt_frame, text="Encrypt & Decrypt")

        ttk.Button(encrypt_decrypt_frame, text="Encrypt New Folder", command=lambda: self.run_in_background(self.encrypt_action), width=40).pack(pady=10)
        ttk.Button(encrypt_decrypt_frame, text="Refresh", command=lambda: self.run_in_background(self.update_folder_display), width=40).pack(pady=10)

        self.canvas = tk.Canvas(encrypt_decrypt_frame)
        self.canvas.pack(side="left", fill="both", expand=True, pady=10)

        scrollbar = ttk.Scrollbar(encrypt_decrypt_frame, orient="vertical", command=self.canvas.yview)
        scrollbar.pack(side="right", fill="y")

        self.folder_display = ttk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.folder_display, anchor="nw")

        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.folder_display.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind_all("<MouseWheel>", self._on_mouse_wheel)

        self.update_folder_display()

    def update_folder_display(self):
        folders = self.encryption_manager.get_all_encrypted_folders()
        for widget in self.folder_display.winfo_children():
            widget.destroy()

        for i, (uuid, folder_path) in enumerate(folders):
            folder_exists = os.path.exists(folder_path)
            entry_frame = ttk.Frame(self.folder_display, padding=5)
            entry_frame.pack(fill="x", pady=2)

            if folder_path == "":
                continue

            folder_label = ttk.Label(entry_frame, text=folder_path, anchor="w", foreground="red" if not folder_exists else "white")
            folder_label.pack(side="left", fill="x", expand=True)

            navigate_button = ttk.Button(entry_frame, text="Open Folder", command=lambda p=folder_path: self.run_in_background(self.open_folder, p))
            navigate_button.pack(side="right", padx=5)

            if folder_exists:
                decrypt_button = ttk.Button(entry_frame, text="Decrypt", command=lambda u=uuid, p=folder_path: self.run_in_background(self.decrypt_folder, u, p))
                decrypt_button.pack(side="right", padx=5)
            else:
                locate_button = ttk.Button(entry_frame, text="Locate", command=lambda u=uuid: self.run_in_background(self.locate_folder, u))
                locate_button.pack(side="right", padx=5)

                delete_button = ttk.Button(entry_frame, text="Delete", command=lambda u=uuid: self.run_in_background(self.delete_folder_entry, u))
                delete_button.pack(side="right", padx=5)

    def _on_mouse_wheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def run_in_background(self, func, *args):
        threading.Thread(target=func, args=args, daemon=True).start()

    def encrypt_action(self):
        folder_path = filedialog.askdirectory(title="Select Folder to Encrypt")
        if not folder_path:
            return

        output_path = folder_path + self.encryption_manager.ENCRYPTED_FILE_EXTENSION
        temp_archive = output_path + ".tar.gz"

        self.encryption_manager.compress_folder(folder_path, output_path)
        self.encryption_manager.encrypt_file(temp_archive, output_path)
        os.remove(temp_archive)  # Clean up the unencrypted archive file

        messagebox.showinfo("Success", "Folder successfully encrypted.")
        self.update_folder_display()

    def decrypt_folder(self, uuid, folder_path):
        output_folder = folder_path.replace(self.encryption_manager.ENCRYPTED_FILE_EXTENSION, self.encryption_manager.DECRYPTED_FOLDER_EXTENSION)
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        temp_archive = os.path.splitext(folder_path)[0] + ".tar.gz"

        try:
            self.encryption_manager.decrypt_file(folder_path, temp_archive)
            self.encryption_manager.decompress_folder(temp_archive, output_folder)
            os.remove(temp_archive)  # Clean up the temporary archive file

            messagebox.showinfo("Success", "Folder successfully decrypted and decompressed.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        self.update_folder_display()

    def open_folder(self, path):
        try:
            os.startfile(os.path.dirname(path))
        except Exception as e:
            messagebox.showerror("Error", f"Opening folder failed: {str(e)}")
        self.update_folder_display()
            
    def locate_folder(self, uuid):
        folder_path = filedialog.askopenfilename(title="Locate Encrypted Folder", filetypes=[("Encrypted Files", "*.enc")])
        if not folder_path:
            return

        key = self.encryption_manager.get_key(uuid)
        with open(folder_path, 'rb') as file:
            file_uuid = file.read().split(b'\n', 1)[0].decode()

        if file_uuid == uuid:
            self.encryption_manager.update_folder_path(uuid, folder_path)
            messagebox.showinfo("Success", "Folder location updated.")
        else:
            messagebox.showerror("Error", "The selected folder does not match the expected UUID.")
        self.update_folder_display()

    def delete_folder_entry(self, uuid):
        del self.encryption_manager.keys[uuid]
        self.encryption_manager.save_keys()
        messagebox.showinfo("Success", "Entry deleted.")
        self.update_folder_display()

    def setup_login_data_tab(self):
        login_frame = ttk.Frame(self.notebook)
        self.notebook.add(login_frame, text="Login Data")

        ttk.Label(login_frame, text="Email:").pack(pady=5)
        self.email_entry = ttk.Entry(login_frame, width=60)
        self.email_entry.pack(pady=5)

        ttk.Label(login_frame, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(login_frame, width=60)
        self.password_entry.pack(pady=5)

        ttk.Label(login_frame, text="Website/Account:").pack(pady=5)
        self.website_entry = ttk.Entry(login_frame, width=60)
        self.website_entry.pack(pady=5)

        ttk.Button(login_frame, text="Add Login Entry", command=lambda: self.run_in_background(self.add_login_entry), width=40).pack(pady=10)

        self.canvas = tk.Canvas(login_frame)
        self.canvas.pack(side="left", fill="both", expand=True, pady=10)

        scrollbar = ttk.Scrollbar(login_frame, orient="vertical", command=self.canvas.yview)
        scrollbar.pack(side="right", fill="y")

        self.login_display = ttk.Frame(self.canvas, style="Custom.TFrame")
        self.canvas.create_window((0, 0), window=self.login_display, anchor="nw")

        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.login_display.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind_all("<MouseWheel>", self._on_mouse_wheel)

        self.update_login_display()

    def update_login_display(self):
        data = self.login_manager.load_login_data()
        for widget in self.login_display.winfo_children():
            widget.destroy()

        for i, entry in enumerate(data):
            entry_frame = ttk.Frame(self.login_display, padding=5)
            entry_frame.pack(fill="x", pady=2)

            website_label = ttk.Label(entry_frame, text=f"Website: {entry['website']}", anchor="w", foreground="orange")
            website_label.pack(side="top", fill="x", expand=True)

            email_label = ttk.Label(entry_frame, text=f"Email: {entry['email']}\nPassword: {entry['password']}", anchor="w")
            email_label.pack(side="left", fill="x", expand=True)

            delete_button = ttk.Button(entry_frame, text="Delete", command=lambda index=i: self.run_in_background(self.delete_login_entry, index))
            delete_button.pack(side="right", padx=5)

            copy_password_button = ttk.Button(entry_frame, text="Copy Password", command=lambda p=entry['password']: self.copy_to_clipboard(p))
            copy_password_button.pack(side="right", padx=5)

            copy_email_button = ttk.Button(entry_frame, text="Copy Email", command=lambda e=entry['email']: self.copy_to_clipboard(e))
            copy_email_button.pack(side="right", padx=5)

            if i < len(data) - 1:
                separator = ttk.Separator(self.login_display, orient="horizontal")
                separator.pack(fill="x", pady=5)

    def copy_to_clipboard(self, text):
        pyperclip.copy(text)

    def add_login_entry(self):
        email = self.email_entry.get()
        password = self.password_entry.get()
        website = self.website_entry.get()
        if email == "" or password == "" or website == "":
            messagebox.showerror("Error", "Make sure all fields are filled.")
        else:
            self.login_manager.add_login_entry(email, password, website)
            self.update_login_display()

    def delete_login_entry(self, index):
        self.login_manager.delete_login_entry(index)
        self.update_login_display()
