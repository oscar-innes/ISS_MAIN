import hashlib
import sys
import socket
from pymongo import MongoClient
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
import logging
import hmac
import requests
import keyring
import stat
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import pyotp
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.DH import key_agreement
import functools
from Crypto.Protocol.KDF import HKDF
import secrets
from Crypto.PublicKey import RSA
import Crypto
from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import bcrypt
import re
import base64
import argon2
from argon2 import PasswordHasher
import qrcode
from io import BytesIO
from base64 import b64encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import time
import jwt
import platform
from dotenv import load_dotenv
import os


def is_otp_valid(username, secret, user_otp):
  thebigone = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="MyFinance")   #create a new totp for a specific user with the secret, so this user is now linked to a google authenticator object
  totp = pyotp.parse_uri(thebigone)
  return totp.verify(user_otp)  #verify the entered code by a user against the code on the google authenticator instance


logging.basicConfig(filename="system.log",
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filemode='w')
logger = logging.getLogger('system')
logger.info("System loaded at: IP=%s")

def get_db():
    reciever = MongoClient("mongodb+srv://cryptoconnector:TheBigHammer123!!&@cluster0.vrpo6.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0", tls=True) 
    return reciever['iss']  #create a reciever object that communicates with the database in a secure TLS channel.

def sanitise_input(string):
    return re.sub('[../+\\n+\\r"\\\']*', '', string) 

def admin_check(username):
    db = get_db()
    user_rolecheck = db.ClientAccounts.find_one({"username": username}, {"role": 1})  #search and find a user and grab the role associated with their entry in the database
    if user_rolecheck:
        if user_rolecheck.get("role") in ["System admin"]:  #if the role is senior, the check is true otherwise false
            return True
        else:
            return False
    else:
        return False
    
def advisor_check(username):
    db = get_db()
    user_rolecheck = db.ClientAccounts.find_one({"username": username}, {"role": 1})  #search and find a user and grab the role associated with their entry in the database
    if user_rolecheck:
        if user_rolecheck.get("role") in ["Financial Advisor"]:  #if the role is senior, the check is true otherwise false
            return True
        else:
            return False
    else:
        return False
    
def sanitise_no(input):
  try:
    no = float(input)  #take a numeric input and make it a float and then return a decimal output that is encoded for sanitisation
    return float("%.2f" % no)
  except ValueError:
    new = re.sub('[^\d.]', '', no)   #if it cant be converted remove values to strip sensitive characters from a float.
    try:
      new = float(new) 
      return new
    except ValueError:
      return None
    
def keygen(passed, salty):
    passy = passed.encode('UTF-8')
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salty,
    iterations=1_000_000)
    key = kdf.derive(passy)
    print(len(key))
    return key

def keyskeyskeys(userhash, passy):
    curvy = ECC.generate(curve='p521')
      #creates a new private key with the users hash, so that specific users private keys can be easily found on the system with ease.
    privvy = curvy.export_key(format='PEM',
                                passphrase=passy,
                                protection='PBKDF2WithHMAC-SHA512AndAES256-GCM', #create a password so even if the system user tries to access it, they need to enter a password.
                                prot_params={'iteration_count':131072})
    publix = curvy.public_key().export_key(format='PEM')
    
    keyring.set_password("ISS", f"{userhash}privkey", privvy)
        

    keyring.set_password("ISS", f"{userhash}publickey", publix)
    print("Registration completed, returning to main menu...")
 #this ensures that noone except the system user can read or modify private key files, it restricts permissions to protect user information.  


def encrypt_customers(key, plain, salt):
    vector = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=vector)
    encrypted_message_byte, tag = cipher.encrypt_and_digest(plain.encode("utf-8"))
    byte = vector + salt + encrypted_message_byte + tag
    encoder = base64.b64encode(byte)
    return bytes.decode(encoder)

def decrypt_customers(username, encrypted, salt):
    load_dotenv(os.path.expanduser("~/.env"))
    key = base64.b64decode(os.getenv(f"{username}"))
    decoded = base64.b64decode(encrypted)
    vector = decoded[:12]
    msg = decoded[(12 + len(salt)):- 16]
    tag = decoded[-16:]
    reverse = AES.new(key, AES.MODE_GCM, nonce=vector)
    finalword = reverse.decrypt_and_verify(msg, tag)
    return finalword.decode('utf-8')
    
def password_check(password):
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password): #usedw3resource here for regex patterns to verify a password is suitably strong
        return False
    return True, "All clear"

def fix_email(email):
    email = re.sub(r'@(\w+)(com)', r'@\1.\2', email) #regex pattern that adds a '.' back into the email as this gets removed during sanitiszation of inputs.
    return email

def get_b64encoded_qr_image(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)  #create a new QR code
    qr.add_data(data)  #add the link to the google authenticator totp for the specific user here
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")

def generate_salt(length=16):
    return secrets.token_hex(length)

def set_env(env_value, value):
    base64value = base64.b64encode(value).decode('utf-8')
    env_file = os.path.expanduser("~/.env")
    with open(env_file, "a") as f:
        f.write(f'{env_value}="{base64value}"\n') #fot future maybe find a way to encrypt/hash username symettrically so if hacker gets access they cant get the keys to each user easily preventing lateral movement.

def exit():
    pass

def register():
    print("To register a new account please enter the following details into the command prompt:")
    username = sanitise_input(input("Enter your username"))
    name = sanitise_input(input("Enter your name"))
    address = sanitise_input(input("Enter your home address"))
    email = sanitise_input(input("Enter your email"))
    postcode = sanitise_input(input("Enter your postcode"))
    country = sanitise_input(input("Enter your country"))
    password = sanitise_input(input("Enter a strong password for the account"))
    username2 = username.encode('UTF-8')
    fix_email(email)
    ph = PasswordHasher()
    while password_check(password) is False:
            print("Password lacks sufficent complexity please retry again") #ensure password cant be cracked and is of suitable strength
            password = input("Enter a strong password for the account")
    fa = input("Do you wish to enable 2fa? Y for Yes and N for NO, this uses google authenticator only").upper()
    match fa:
        case "Y":
            secret_token = pyotp.random_base32()
            salty = generate_salt().encode()
            passed = password.encode('UTF-8')
            userhash = ph.hash(username2, salt=salty) #argon2 hash for security
            db = get_db()
            keys = keygen(password, salty)
            encemail = encrypt_customers(keys, email, salty)
            encaddress = encrypt_customers(keys, address, salty)
            encname = encrypt_customers(keys, name, salty)
            encpostcode = encrypt_customers(keys, postcode, salty)
            encountry = encrypt_customers(keys, country, salty)
            enc_token = encrypt_customers(keys, secret_token, salty)
            hash = ph.hash(passed, salt=salty)
            time = datetime.now()
            file = {
                    "username": f"{username}",
                    "password": f"{hash}",
                    "email": f"{encemail}",
                    "postcode": f"{encpostcode}",
                    "createdat": f"{time}",
                    "address": f"{encaddress}",
                    "country": f"{encountry}",
                    "fullname": f"{encname}",
                    "role": "Client",
                    "salt": f"{salty.decode()}",
                    "token": f"{enc_token}",
                    "userhash": f"{userhash}"

            }
            insert = db.ClientAccounts.insert_one(file)
            if insert:
                totp_auth = pyotp.totp.TOTP(secret_token).provisioning_uri( 
                name=username, issuer_name='MyFinance')   
                print(totp_auth)#generate a new TOTP for 2fa authentication being used for this user
                qr = qrcode.QRCode(version=1, box_size=2, border=1)  
                qr.add_data(totp_auth)
                qr.make()
                print("Please scan the below code to get setup with google authenticator, add a new authenticator option selected")
                qr.print_ascii() #get the qr code used to link the user to a 2fa secret via google authenticator
                logger.info(f"Account {username} created with 2fa enabled.") 
                set_env(username, keys)
                keyskeyskeys(userhash, passed)
                open_connection()

                
        case "N":
            salty = generate_salt().encode()
            passed = password.encode('UTF-8')
            userhash = ph.hash(username2, salt=salty) #argon2 hash for security
            db = get_db()
            keys = keygen(password, salty)
            encemail = encrypt_customers(keys, email, salty)
            encaddress = encrypt_customers(keys, address, salty)
            encname = encrypt_customers(keys, name, salty)
            encpostcode = encrypt_customers(keys, postcode, salty)
            encountry = encrypt_customers(keys, country, salty)
            hash = ph.hash(passed, salt=salty)
            time = datetime.now()
            file = {
                    "username": f"{username}",
                    "password": f"{hash}",
                    "email": f"{encemail}",
                    "postcode": f"{encpostcode}",
                    "createdat": f"{time}",
                    "address": f"{encaddress}",
                    "country": f"{encountry}",
                    "fullname": f"{encname}",
                    "role": "Client",
                    "salt": f"{salty.decode()}",
                    "token": "no",
                    "userhash": f"{userhash}"

            }
            insert = db.ClientAccounts.insert_one(file)
            if insert:
                logger.info(f"Account {username} created with 2fa enabled.") 
                set_env(username, keys)
                keyskeyskeys(userhash, passed)
                open_connection()
        case _: 
            while fa is not "y".upper() or "n".upper():
                print("Please enter Y or N no other inputs please")
                fa = input("Do you wish to enable 2fa? Y for Yes and N for NO").upper()

    

def open_connection():
    welcome = input("Welcome to the MyFinance Cryptosystem! Please select one of the following options to begin \n"
    "1 - Register a new account \n"
    "2 - Login to the system \n"
    "3 - Exit \n")

    match welcome: #system requires python 3.10 or higher pls install
        case "1":
            register()
        case "2":
            login()
        case "3":
            exit()
        case _:
            print("Exiting command line now!")
            pass


def account_menu(username):
    if admin_check(username):
        pass
    elif admin_check(username):
        pass
    else:
        pass


def login():
    print("To login please enter the following details:")
    username = sanitise_input(input("Enter username for your account"))
    password = sanitise_input(input("Please enter your password"))
    username2 = username.encode('UTF-8')
    passed = password.encode('UTF-8')
    ph = PasswordHasher()
    db = get_db()
    exists = db.ClientAccounts.find_one({"username": f"{username}"})
    if exists:
        passy = exists.get("password")
        salty = exists.get("salt")
        token = exists.get("token")
        role = exists.get('role')
        groups = exists.get('group')
        salt = str(salty).encode('UTF-8')
        userhash = ph.hash(username2, salt=salt)
        if ph.hash(passed, salt=salt) == passy:
            if token != "no":
                tonkatoken = decrypt_customers(username, token, salt)
                onetime = sanitise_input(input("Enter your otp code from your authenticator app"))
                while is_otp_valid(username, tonkatoken, onetime) == False:
                    onetime = sanitise_input("Enter your otp code from your authenticator app")
                retrieval = keyring.get_password("ISS", f"{userhash}privkey")
                if retrieval:
                    private_key = serialization.load_pem_private_key(retrieval.encode(), password=passed)
                    payload = {
                        "username": username,
                        "role": role,
                        "groups": groups,
                        "iss": "MyFinance System",
                        "exp": 1371720939
                    }
                    token = jwt.encode(payload, private_key, algorithm="ES512")
                    print(token)
                    account_menu()
                
                else:
                    print("File access is fucked")
            else:
                print("Read tonka as no")
        else:
            print("hash not verified")
    else:
        print("cant find in database")





if __name__ == "__main__":
    open_connection()