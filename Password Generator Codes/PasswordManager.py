import customtkinter as ctk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet
from datetime import datetime
import hashlib
import os
import secrets
import string

# ========================== SETUP =========================== #
APP_VERSION = "0.2.0"

# Check for Updates and Show Patch Notes
def check_for_updates():
    version_file = "version.txt"
    if os.path.exists(version_file):
        with open(version_file, "r") as f:
            saved_version = f.read().strip()
        if saved_version != APP_VERSION:
            show_patch_notes()
            with open(version_file, "w") as f:
                f.write(APP_VERSION)
    else:
        with open(version_file, "w") as f:
            f.write(APP_VERSION)


def show_patch_notes():
    if not os.path.exists("patch_notes.txt"):
        messagebox.showwarning("Warning", "No patch notes found!")
        return

    with open("patch_notes.txt", "r") as f:
        patch_notes = f.read()

    messagebox.showinfo("Patch Notes", patch_notes)


# Encryption Key Setup
key_file = "key.key"

if not os.path.exists(key_file):
    with open(key_file, "wb") as f:
        f.write(Fernet.generate_key())

with open(key_file, "rb") as f:
    key = f.read()

cipher = Fernet(key)

# Master Password Setup (Using Hashing for Security)
MASTER_PASSWORD_HASH = hashlib.sha256("mypassword".encode()).hexdigest()


# ========================== FUNCTIONS =========================== #
# Master password check
def verify_master_password():
    entered_password = simpledialog.askstring(
        "Master Password", "Enter the master password:", show="*"
    )
    if not entered_password:
        return False

    entered_hash = hashlib.sha256(entered_password.encode()).hexdigest()
    if entered_hash == MASTER_PASSWORD_HASH:
        return True
    else:
        messagebox.showerror("Error", "Incorrect master password!")
        return False


# Generate a random password
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))


# Save password with option to randomize
def save_password():
    if not verify_master_password():
        return

    # Get label/description
    label = simpledialog.askstring("Input", "Enter a label/description for this password:")
    if not label:
        messagebox.showwarning("Warning", "Label cannot be empty!")
        return

    # Ask user to choose between manual or randomized password
    choice = messagebox.askyesno("Password Choice", "Do you want to generate a random password?")
    if choice:
        length = simpledialog.askinteger("Password Length", "Enter the length of the password (8-32):", minvalue=8, maxvalue=32)
        if not length:
            return
        password = generate_random_password(length)
        messagebox.showinfo("Generated Password", f"Generated Password: {password}")
    else:
        password = simpledialog.askstring("Input", "Enter the password manually:")
        if not password:
            messagebox.showwarning("Warning", "Password cannot be empty!")
            return

    # Save encrypted password with a timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    encrypted_password = cipher.encrypt(password.encode()).decode()

    with open("passwords.txt", "a") as f:
        f.write(f"{label} | {timestamp} | {encrypted_password}\n")

    messagebox.showinfo("Success", "Password saved successfully!\nRemember to back up your key.key file!")


# View passwords
def view_passwords():
    if not verify_master_password():
        return

    if not os.path.exists("passwords.txt"):
        messagebox.showwarning("Warning", "No passwords stored yet!")
        return

    with open("passwords.txt", "r") as f:
        lines = f.readlines()

    if not lines:
        messagebox.showinfo("Info", "No passwords to display!")
        return

    decrypted_passwords = ""
    for line in lines:
        try:
            label, timestamp, encrypted_password = line.strip().split(" | ")
            decrypted_password = cipher.decrypt(encrypted_password.encode()).decode()
            decrypted_passwords += f"{label} ({timestamp}): {decrypted_password}\n"
        except Exception:
            decrypted_passwords += f"Error decrypting line: {line}\n"

    messagebox.showinfo("Stored Passwords", decrypted_passwords)


# ========================== GUI SETUP =========================== #
# Run the update check before launching the GUI
check_for_updates()

# Main App
app = ctk.CTk()
app.title(f"Modern Password Manager - v{APP_VERSION}")
app.geometry("400x400")

# Set theme
ctk.set_appearance_mode("dark")  # Modes: "system" (default), "dark", "light"
ctk.set_default_color_theme("blue")  # Themes: "blue", "green", "dark-blue"

# Title Label
title_label = ctk.CTkLabel(app, text="Password Manager", font=("Arial", 24, "bold"))
title_label.pack(pady=20)

# Buttons
save_button = ctk.CTkButton(app, text="Save Password", command=save_password, width=200)
save_button.pack(pady=10)

view_button = ctk.CTkButton(app, text="View Passwords", command=view_passwords, width=200)
view_button.pack(pady=10)

patch_notes_button = ctk.CTkButton(app, text="Patch Notes", command=show_patch_notes, width=200)
patch_notes_button.pack(pady=10)

exit_button = ctk.CTkButton(app, text="Exit", command=app.quit, fg_color="red", hover_color="darkred", width=200)
exit_button.pack(pady=10)

# Run Main Loop
app.mainloop()
