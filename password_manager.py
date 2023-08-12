from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# generate cryptographic key, use only once for now
# def write_key():
#     key = Fernet.generate_key()
#     with open("key.key", 'wb') as key_file:
#         key_file.write(key)

def read_key():
    file = open("key.key", "rb")
    key = file.read()
    file.close()
    return key

def mode():
    master_pwd = input("State your master password: ")
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=480000,)
    key = base64.urlsafe_b64encode(kdf.derive(read_key()+master_pwd.encode()))

    # key = read_key()+master_pwd.encode()
    fer = Fernet(key)
    while True:
        mode = input("Would you like to add a new password or view an existing password? (add/view) || Press Q to quit ").lower()
        if mode == "q":
            break
        elif mode == "add":
            add(fer)
        elif mode == "view":
            view(fer)
        else:
            print("Invalid mode!")

def add(fer):
    account_name = input("Account Name: ")
    pwd = input("New Password: ")
    token = fer.encrypt(pwd.encode())
    with open("passwords.txt", "a") as f:
        f.write(account_name + " | " + str(token) + "\n")
    return token

def view(fer):
    with open("passwords.txt", "r") as f:
        for line in f.readlines():
            data = line.rstrip()
            user, passw = data.split(' | ')
            print(f"User: {user} | Password: {(fer.decrypt(fer.encrypt(passw.encode()))).decode()}")

def run_manager():
    mode()

run_manager()