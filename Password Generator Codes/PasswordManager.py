import customtkinter as ctk
from tkinter import messagebox, simpledialog, StringVar
from cryptography.fernet import Fernet
from datetime import datetime
import os
import secrets
import string

# ========================== SETUP =========================== #

APP_VERSION = "0.3.0"

# Show the app version
def show_version():
    messagebox.showinfo("App Version", f"Current Version: {APP_VERSION}")

def show_patch_notes():
    patch_notes_path = r"C:/Users/minai/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Python 3.13/Python_Projects/Password Generator/patch_notes.txt"
    if not os.path.exists(patch_notes_path):
        messagebox.showwarning("Warning", "No patch notes found!")
        return

    with open(patch_notes_path, "r") as f:
        patch_notes = f.read()

    messagebox.showinfo("Patch Notes", patch_notes)

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

check_for_updates()  # Call this at the start of the app

# Generate or load the encryption key
key_file = "key.key"

if not os.path.exists(key_file):
    with open(key_file, "wb") as f:
        f.write(Fernet.generate_key())

with open(key_file, "rb") as f:
    key = f.read()

cipher = Fernet(key)

# Set the master password
MASTER_PASSWORD = "mypassword"  # Change this to your preferred master password

# ========================== FUNCTIONS =========================== #
# Analyze password strength dynamically
def analyze_password_strength(password):
    length = len(password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digits = any(char.isdigit() for char in password)
    has_special = any(char in string.punctuation for char in password)

    # Calculate entropy (approximation)
    pool_size = 0
    if has_upper: pool_size += 26
    if has_lower: pool_size += 26
    if has_digits: pool_size += 10
    if has_special: pool_size += len(string.punctuation)

    entropy = length * (pool_size.bit_length() if pool_size > 0 else 0)

    # Strength categorization
    if length >= 12 and has_upper and has_lower and has_digits and has_special and entropy >= 80:
        return "Strong"
    elif length >= 8 and (has_upper or has_lower) and (has_digits or has_special) and entropy >= 50:
        return "Moderate"
    else:
        return "Weak"

# Generate a strong random password with a specific length
def generate_strong_random_password(length=12):
    while True:
        password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length))
        if analyze_password_strength(password) == "Strong":
            return password

# Save password with integrated input and randomization
def save_password():
    if not verify_master_password():
        return

    # Show combined label and password input dialog
    while True:
        label, password = show_label_password_input_dialog()
        if not label or not password:
            return

        # Check for duplicate label or password
        if is_duplicate(label, password):
            messagebox.showwarning("Warning", "This label or password already exists!")
            continue  # Go back to the input dialog if there's a duplicate

        # Save encrypted password with a timestamp
        timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        encrypted_password = cipher.encrypt(password.encode()).decode()

        with open("passwords.txt", "a") as f:
            f.write(f"{label} | {timestamp} | {encrypted_password}\n")

        messagebox.showinfo("Success", "Password saved successfully!")
        break  # Exit the loop once the password is saved

def is_duplicate(label, password):
    """Check if the label or password already exists in the passwords file"""
    if not os.path.exists("passwords.txt"):
        return False

    with open("passwords.txt", "r") as f:
        lines = f.readlines()

    for line in lines:
        existing_label, _, encrypted_password = line.strip().split(" | ")
        decrypted_password = cipher.decrypt(encrypted_password.encode()).decode()
        if existing_label == label or decrypted_password == password:
            return True

    return False

# Master password check
def verify_master_password():
    entered_password = simpledialog.askstring(
        "Master Password", "Enter the master password:", show="*"
    )
    if entered_password == MASTER_PASSWORD:
        return True
    else:
        messagebox.showerror("Error", "Incorrect master password!")
        return False

# Show stored passwords
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

# Show combined label and password input dialog
def show_label_password_input_dialog():
    input_window = ctk.CTkToplevel()
    input_window.title("Save Password")
    input_window.geometry("400x350")  # Increase height to accommodate new layout

    label_var = StringVar()
    password_var = StringVar()
    length_var = StringVar(value="12")  # Default password length set to 12
    strength_label = ctk.CTkLabel(input_window, text="Strength: Weak", font=("Arial", 14))

    # Enter Label/Description field
    ctk.CTkLabel(input_window, text="Enter Label/Description", font=("Arial", 14)).pack(pady=5)
    label_entry = ctk.CTkEntry(input_window, textvariable=label_var, width=200, justify="center")  # Text aligned to the center
    label_entry.pack(pady=3, padx=15)

    # Enter Password field
    ctk.CTkLabel(input_window, text="Enter Password", font=("Arial", 14)).pack(pady=5)
    
    # Create a frame to hold the password entry and the eye icon
    password_frame = ctk.CTkFrame(input_window)
    password_frame.pack(pady=3, fill="x", padx=15)

    # Set the same width for the password entry as the label entry, and center the text
    password_entry = ctk.CTkEntry(password_frame, textvariable=password_var, show="*", width=200, justify="center")  # Text aligned to the center
    password_entry.pack(side="left", fill="x", expand=True)

    # Eye icon for toggling password visibility
    eye_icon = ctk.CTkButton(password_frame, text="👁", width=40, command=lambda: toggle_password_visibility(password_entry))
    eye_icon.pack(side="right")

    def toggle_password_visibility(entry):
        current_show = entry.cget("show")
        new_show = "" if current_show == "*" else "*"
        entry.configure(show=new_show)

    def on_password_change(*args):
        password = password_var.get()
        strength = analyze_password_strength(password)
        strength_label.configure(text=f"Strength: {strength}")

    password_var.trace("w", on_password_change)

    # Strength label below the password entry
    strength_label.pack(pady=5)

    def randomize_password():
        try:
            length = int(length_var.get())
            # Length validation
            if length <= 0 or length > 20:
                raise ValueError("Length must be between 1 and 20.")
            password = generate_strong_random_password(length)
            password_var.set(password)
            strength_label.configure(text="Strength: Strong")
        except ValueError as e:
            messagebox.showerror("Invalid Length", str(e))

    # Frame to hold password length and randomizer button side by side
    length_randomize_frame = ctk.CTkFrame(input_window)
    length_randomize_frame.pack(pady=5, padx=15, fill="x")

    # Label and entry for password length
    ctk.CTkLabel(length_randomize_frame, text="Password Length (8-20)", font=("Arial", 14)).pack(side="left", padx=5)

    # Password Length Entry
    length_entry = ctk.CTkEntry(length_randomize_frame, textvariable=length_var, width=50)  # Adjusted width
    length_entry.pack(side="left", padx=5)

    # Randomizer button beside the length entry
    randomize_button = ctk.CTkButton(length_randomize_frame, text="Randomize", command=randomize_password)
    randomize_button.pack(side="left", padx=5)

    def confirm_inputs():
        input_window.destroy()

    confirm_button = ctk.CTkButton(input_window, text="Confirm", command=confirm_inputs)
    confirm_button.pack(pady=10)

    input_window.grab_set()
    input_window.wait_window()
    return label_var.get(), password_var.get()





# ========================== GUI SETUP =========================== #
# Main App
app = ctk.CTk()
app.title(f"Michael's Password Manager v{APP_VERSION}")
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
