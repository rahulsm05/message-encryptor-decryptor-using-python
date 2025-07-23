from tkinter import *
from tkinter import messagebox, filedialog
import base64
import hashlib
import pyperclip  # For clipboard functionality

# Encrypt using Base64
def encrypt_base64(message):
    return base64.b64encode(message.encode()).decode()

# Decrypt using Base64
def decrypt_base64(encrypted_message):
    return base64.b64decode(encrypted_message).decode()

# Hashing functions
def hash_md5(message):
    return hashlib.md5(message.encode()).hexdigest()

def hash_sha256(message):
    return hashlib.sha256(message.encode()).hexdigest()

def encrypt():
    password = code.get()
    if password == "5431":
        screen1 = Toplevel(screen)
        screen1.title("Encryption")
        screen1.geometry("400x400")
        screen1.configure(bg="#ed3833")

        message = text1.get(1.0, END).strip()
        if not message:
            messagebox.showerror("Encryption", "Input message to encrypt")
            return

        # Encrypt the message using Base64
        encrypted_message = encrypt_base64(message)

        Label(screen1, text="ENCRYPT", font="arial", fg="white", bg="#ed3833").place(x=10, y=0)
        text2 = Text(screen1, font="RPbote 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10, y=40, width=380, height=200)

        text2.insert(END, encrypted_message)

        # Show hash values
        md5_hash = hash_md5(message)
        sha256_hash = hash_sha256(message)
        text2.insert(END, f"\n\nMD5: {md5_hash}\nSHA-256: {sha256_hash}")

        # Add copy button
        Button(screen1, text="Copy Encrypted Output", command=lambda: copy_to_clipboard(encrypted_message), bg="#1089ff", fg="white").place(x=10, y=250)

    elif password == "":
        messagebox.showerror("Encryption", "Input Password")
    elif password != "5431":
        messagebox.showerror("Encryption", "Invalid Password")

def decrypt():
    password = code.get()
    if password == "4321":
        screen2 = Toplevel(screen)
        screen2.title("Decryption")
        screen2.geometry("400x400")
        screen2.configure(bg="#00bd56")

        message = text1.get(1.0, END).strip()
        if not message:
            messagebox.showerror("Decryption", "Input message to decrypt")
            return

        try:
            # Decrypt the message using Base64
            decrypted_message = decrypt_base64(message)

            Label(screen2, text="DECRYPT", font="arial", fg="white", bg="#00bd56").place(x=10, y=0)
            text2 = Text(screen2, font="RPbote 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
            text2.place(x=10, y=40, width=380, height=200)

            text2.insert(END, decrypted_message)

            # Show hash values
            md5_hash = hash_md5(decrypted_message)
            sha256_hash = hash_sha256(decrypted_message)
            text2.insert(END, f"\n\nMD5: {md5_hash}\nSHA-256: {sha256_hash}")

            # Add copy button
            Button(screen2, text="Copy Decrypted Output", command=lambda: copy_to_clipboard(decrypted_message), bg="#1089ff", fg="white").place(x=10, y=250)

        except Exception as e:
            messagebox.showerror("Decryption", "Error during decryption: " + str(e))

    elif password == "":
        messagebox.showerror("Decryption", "Input Password")
    elif password != "4321":
        messagebox.showerror("Decryption", "Invalid Password")

def copy_to_clipboard(text):
    pyperclip.copy(text)
    messagebox.showinfo("Copy to Clipboard", "Text copied to clipboard!")

def encrypt_file():
    password = code.get()
    if password == "5431":
        file_path = filedialog.askopenfilename(title="Select a file to encrypt")
        if not file_path:
            return

        with open(file_path, 'r') as file:
            message = file.read()

        # Encrypt the message using Base64
        encrypted_message = encrypt_base64(message)

        # Save the encrypted message to a new file
        with open(file_path + ".enc", 'w') as encrypted_file:
            encrypted_file.write(encrypted_message)

        messagebox.showinfo("File Encryption", f"File encrypted successfully: {file_path}.enc")

def decrypt_file():
    password = code.get()
    if password == "4321":
        file_path = filedialog.askopenfilename(title="Select a file to decrypt")
        if not file_path:
            return

        try:
            with open(file_path, 'r') as file:
                encrypted_message = file.read()

            # Decrypt the message using Base64
            decrypted_message = decrypt_base64(encrypted_message)

            # Save the decrypted message to a new file
            with open(file_path.replace(".enc", ".dec"), 'w') as decrypted_file:
                decrypted_file.write(decrypted_message)

            messagebox.showinfo("File Decryption", f"File decrypted successfully: {file_path.replace('.enc', '.dec')}")

        except Exception as e:
            messagebox.showerror("Decryption", "Error during decryption: " + str(e))

# Create the main application window
screen = Tk()
screen.title("Message E&D")
screen.geometry("500x500")
screen.configure(bg="#f0f0f0")

# Input for password
code = StringVar()
Label(screen, text="Enter Password", bg="#f0f0f0").pack(pady=10)
Entry(screen, textvariable=code, show='*').pack(pady=10)

# Text area for input message
text1 = Text(screen, height=10, width=50, bg="white", relief=GROOVE, wrap=WORD, bd=0)
text1.pack(pady=10)

# Buttons for encrypting and decrypting
Button(screen, text="Encrypt", command=encrypt, bg="#ed3833", fg="white").pack(pady=5)
Button(screen, text="Decrypt", command=decrypt, bg="#00bd56", fg="white").pack(pady=5)
Button(screen, text="Encrypt File", command=encrypt_file, bg="#ed3833", fg="white").pack(pady=5)
Button(screen, text="Decrypt File", command=decrypt_file, bg="#00bd56", fg="white").pack(pady=5)

# Run the Tkinter event loop
screen.mainloop()

main_screen()