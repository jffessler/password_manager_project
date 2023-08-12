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

#read the cryptographic key from the key file, this can be set up to have multiple and rotating keys
def read_key():
    file = open("key.key", "rb")
    key = file.read()
    file.close()
    return key

#mode selection and the definition of the master key for both returning and new users
def mode():
    master_pwd = input("State your master password: ")

    while True:
        mode = input("Would you like to add a new password or view an existing password? (add/view) || Press Q to quit ").lower()
        if mode == "q":
            break
        elif mode == "add":
            add(master_pwd)
        elif mode == "view":
            view(master_pwd)
        else:
            print("Invalid mode!")

#function for the addition of new data
def add(master_pwd):
    #defining the key tied to each password
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=480000,)
    key = base64.urlsafe_b64encode(kdf.derive(read_key()+master_pwd.encode()))
    fer = Fernet(key)

    #account and password input and defining the data to be stored for subsequent retrieval and decryption
    account_name = input("Account Name: ")
    pwd = input("New Password: ")
    token = fer.encrypt(pwd.encode())
    with open("passwords.txt", "a") as f:
        f.write(account_name + " | " + token.decode() + " | " + key.decode() + " | " + master_pwd + "\n")
    print(fer.decrypt(token))

#function for the viewing of stored data
def view(master_pwd):
    with open("passwords.txt", "r") as f:
        for line in f.readlines():
            data = line.rstrip()
            user, passw, key, master_pwd_o = data.split(' | ')
            f = Fernet(key)

            #decrypting based on the input of the master key
            if master_pwd == master_pwd_o:
                decoded = f.decrypt(passw.encode())
                print(f"Account: {user} | Password: {decoded}")
            else:
                print("You don't have access to that password")

def run_manager():
    mode()

run_manager()