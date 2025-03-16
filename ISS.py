import ssl
import socket
import time
import atexit
import logging
import datetime
import subprocess
from pymongo import MongoClient
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import pyotp
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.DH import key_agreement
import functools
from Crypto.Protocol.KDF import HKDF
import secrets
import re
import base64
from argon2 import PasswordHasher
import qrcode
from io import BytesIO
from base64 import b64encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import jwt
from dotenv import load_dotenv
import os
import traceback
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import logging.config

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {  
        'verbose': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        },
        'simple': {
            'format': '%(levelname)s %(message)s',
        },
    },
    'handlers': {
        "file": {
            "class": 'logging.FileHandler',
            "level": "INFO",
            'filename': os.path.join(BASE_DIR, 'system.log'),
            'formatter': 'verbose',
        },
        "talk": {
            "class": 'logging.FileHandler',
            "level": "INFO",
            'filename': os.path.join(BASE_DIR, 'chat.log'),
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'system': {  
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': False,
        },
        'chat': {  
            'handlers': ['talk'],
            'level': 'INFO',
            'propagate': False,
        }
    }
}
logging.config.dictConfig(LOGGING)
system_logger = logging.getLogger('system')
chat_logger = logging.getLogger('chat')

try:
    with open("system.key", "rb") as f:
        k = f.read()
    key = Fernet(k)
    for log_file in ['chat.log', 'system.log']:
        with open(log_file, "rb") as file:
            deccers = file.read()
        decrypted = key.decrypt(deccers)
        with open(log_file, "wb") as file2:
            file2.write(decrypted)
except Exception as e:
    pass

def is_otp_valid(username, secret, user_otp):
  thebigone = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="MyFinance")   #create a new totp for a specific user with the secret, so this user is now linked to a google authenticator object
  totp = pyotp.parse_uri(thebigone)
  return totp.verify(user_otp)  #verify the entered code by a user against the code on the google authenticator instance

def refresher():
    pass

def get_db():
    reciever = MongoClient("mongodb+srv://cryptoconnector:TheBigHammer123!!&@cluster0.vrpo6.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0", tls=True) 
    return reciever['iss']  #create a reciever object that communicates with the database in a secure TLS channel.

def sanitise_input(string):
    return re.sub('[../+\\n+\\r"\\\']*', '', string) 

def admin_check(username):
    db = get_db()
    user_rolecheck = db.ClientAccounts.find_one({"username": username}, {"role": 1})  #search and find a user and grab the role associated with their entry in the database
    if user_rolecheck:
        if user_rolecheck.get("role") in ["System Admin"]:  #if the role is senior, the check is true otherwise false
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
    system_logger.debug("A new symmetric encryption key was generated")
    return key

def keyskeyskeys(userhash, salt, key, username):
    curvy = ECC.generate(curve='p521')
      #creates a new private key with the users hash, so that specific users private keys can be easily found on the system with ease.
    privvy = curvy.export_key(format='PEM',
                                protection='PBKDF2WithHMAC-SHA512AndAES256-GCM', #create a password so even if the system user tries to access it, they need to enter a password.
                                prot_params={'iteration_count':131072})
    publix = curvy.public_key().export_key(format='PEM')
    
    f = open(f"{username}privkey.pem", "w")
    f.write(encrypt_customers(key, privvy, salt))
    f.close()
    f2 = open(f"{username}pubkey.pem", "w")
    f2.write(encrypt_customers(key, publix, salt))
    f2.close()
    
    system_logger.debug(f"Asymmetric Keys created for userhash {username}")
    print("Registration completed, returning to main menu...")
 #this ensures that noone except the system user can read or modify private key files, it restricts permissions to protect user information.  

def initate_transaction(username, userhash):
    db = get_db()
    transaction_start = input("Hello welcome to the transaction portal for clients, this is where you can make transactions for approval from your advisors for investments \n"
    "1 - Initiate Transaction for your portfolio \n"
    "2 - Return to the menu \n")
    try:
        match transaction_start:
            case "1":
                exists = db.ClientAccounts.find_one({"username": f"{username}"}, {"salt": 1, "group": 1})
                volla = validate(username, userhash)
                if exists and volla:
                    usergroup = exists.get('group')  #search and find a user and grab the role associated with their entry in the database
                    grouping = db.CompanyPortfolios.find_one({"company_name": f"{usergroup}"}, {"members": 1})
                    if username in grouping.get('members') and usergroup != "none":
                        recp = sanitise_input(input("Enter the company you want to wire funds to"))
                        amount = sanitise_input(input("Enter the amount you want to wire to the recipient"))
                        darpa = db.CompanyPortfolios.find_one({"company_name": f"{recp}"})
                        while not darpa or recp == grouping:
                            recp = sanitise_input(input("Enter the company you want to wire funds to"))
                            darpa = db.CompanyPortfolios.find_one({"sender_group": f"{recp}"})
                        salt = db.ClientAccounts.find_one({"username": username}, {"salt": 1})
                        with open(f"{username}privkey.pem", "rb") as f:
                            line = f.read()
                        retrieval = decrypt_customers(username, line, salt.get('salt'))
                        private_key = ECC.import_key(retrieval)
                        newkey = private_key.export_key(format="PEM")
                        other_key = serialization.load_pem_private_key(
                            newkey.encode('utf-8'),
                            password=None
                        )
                        load_dotenv(os.path.expanduser(".env"))
                        key = base64.b64decode(os.getenv(f"{username}"))
                        message = str(username).encode()
                        salt1 = exists.get('salt')
                        betteramount = encrypt_customers(key, amount, str(salt1).encode())
                        approved_by = encrypt_customers(key, "N/A", str(salt1).encode())
                        sender = encrypt_customers(key, recp, str(salt1).encode())
                        signature = other_key.sign(message, ec.ECDSA(hashes.SHA512()))
                        siggy = encrypt_customers(key, signature.hex(), str(salt1).encode())
                        file = {
                        "initiated_by": f"{username}",
                        "approved_by": f"{approved_by}",
                        "approved": False,
                        "amount": f"{betteramount}",
                        "timestamp": f"{datetime.now()}",
                        "sender_group": f"{sender}",
                        "signature": f"{siggy}"
                        }
                        insert = db.Transactions.insert_one(file)
                        if insert:
                            system_logger.info(f"{username}s has started a transaction to send {amount} to {sender}")
                            print("Transaction submitted for validation and approval from an advisor, please contact your advisor on the chat application if you have any concerns")
                            time.sleep(5)
                            account_menu(username, userhash)
                        else:
                            print("Failed insertion returning to main menu")
                            time.sleep(5)
                            account_menu(username, userhash)
                    else:
                        print("User is not in this group or possibly any groups, contact an admin to be added returning to menu!")
                        system_logger.debug(f"{username} tried to start a transaction but is not a groups member")
                        time.sleep(5)
                        account_menu(username, userhash)

                else:
                    print("Username not found in database or authentication expired, please relogin or create a new account, returning to main account space.")
                    open_connection()

            case "2":
                account_menu(username, userhash)
    except Exception as e:
        system_logger.warning(f"{username}s JWT expired or was invalidated!")
        print("unexpected error occured, returning to login menu")
        account_menu(username, userhash)


def encrypt_customers(key, plain, salt):
    vector = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=vector)
    print(key)
    encrypted_message_byte, tag = cipher.encrypt_and_digest(plain.encode("utf-8"))
    byte = vector + salt + encrypted_message_byte + tag
    encoder = base64.b64encode(byte)
    return bytes.decode(encoder)

def decrypt_customers(username, encrypted, salt):
    load_dotenv(os.path.expanduser(".env"))
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
    env_file = os.path.expanduser(".env")
    with open(env_file, "a") as file:
        file.write(f'{env_value}="{base64value}"\n')

def exit():
    try:
        if os.environ["JWT_CLAIM"]:
            os.environ["JWT_CLAIM"] is None
            print("Disconnected from account")
        else:
            print("Disconnected from account")
    except Exception as e:
        pass

def validate(username, userhash):
    token = os.getenv("JWT_CLAIM")
    db = get_db()
    salt = db.ClientAccounts.find_one({"username": username}, {"salt": 1})
    with open(f"{username}pubkey.pem", "rb") as f:
        line = f.read()
    retrieval = decrypt_customers(username, line, salt.get('salt'))
    public_key = ECC.import_key(retrieval)
    newkey = public_key.export_key(format="PEM")
    jamack = jwt.decode(token, key=newkey, options={"require": ["exp", "iss", "role"]}, algorithms=['ES512',])
    if jamack:
        system_logger.info(f"JWT for {username} decoded and validated successfully!")
        return jamack
        
    else:
        system_logger.critical(f"JWT for {username} failed authentication checks and needs investigating")
        return False

def account_info(username, userhash):
    db = get_db()
    exists = db.ClientAccounts.find_one({"username": f"{username}"})
    transactions = list(db.Transactions.find({}))
    postcode = exists.get("postcode")
    address = exists.get("address")
    salty = exists.get("salt")
    email = exists.get("email")
    groups = exists.get('group')
    country = exists.get('country')
    naming = exists.get('fullname')
    passy = exists.get('password')
    salt = str(salty).encode('UTF-8')
    relevantspend = []
    for item in transactions:
        if username == item['initiated_by'] or item['approved_by']:
            relevantspend.append(item)
    decpostcode = decrypt_customers(username, postcode, salt)
    decaddress = decrypt_customers(username, address, salt)
    decemail = decrypt_customers(username, email, salt)
    decountry = decrypt_customers(username, country, salt)
    decname = decrypt_customers(username, naming, salt)
    bellagarde = validate(username, userhash)
    if bellagarde is not False and exists:
        print(f"Your details for account - {username} \n"
        f"Full name - {decname} \n"
        f"Address - {decaddress} \n"
        f"Postcode - {decpostcode} \n"
        f"Email - {decemail} \n"
        f"Country - {decountry} \n"
        f"Groups - {groups} \n"
        )
        print("Transaction history: \n")
        for thing in relevantspend:
            if thing['initiated_by'] == username:
                amount = decrypt_customers(thing['initiated_by'], thing['amount'], salty)
                sender_group = decrypt_customers(thing['initiated_by'], thing['sender_group'], salty)
                if thing['approved'] == True:
                    print(f" Transaction: {thing['initiated_by']}, {thing['timestamp']}, Sent to: {sender_group} Amount: {amount} and approved by {thing['approved_by']}")
                else:
                    print(f"Transaction: {thing['initiated_by']}, {thing['timestamp']}, Sent to: {sender_group} Amount: {amount} NOT APPROVED")
        relevantspend.clear()
        system_logger.info(f"{username}s accessed their account and transaction information")
        time.sleep(7)
        mortomorto = input("Would you like to return to the menu now or would you like to modify details? \n"
        "1 - Return to menu \n"
        "2 - Modify details \n")
        match mortomorto:
            case "1":
                account_menu(username, userhash)
            case "2":
                addressupdate = sanitise_input(input("Enter changes to home address (LEAVE BLANK/PRESS ENTER FOR NO CHANGE)"))
                if not addressupdate:
                    addressupdate = decaddress
                emailed = sanitise_input(input("Enter your email (LEAVE BLANK/PRESS ENTER FOR NO CHANGE)"))
                if not emailed:
                    emailed = decemail
                posty = sanitise_input(input("Enter your postcode (LEAVE BLANK/PRESS ENTER FOR NO CHANGE)"))
                if not posty:
                    posty = decpostcode
                nation = sanitise_input(input("Enter your country (LEAVE BLANK/PRESS ENTER FOR NO CHANGE)"))
                if not nation:
                    nation = decountry
                named = sanitise_input(input("Enter your name (LEAVE BLANK/PRESS ENTER FOR NO CHANGE)"))
                if not named:
                    named = decname
                ph = PasswordHasher()
                password = sanitise_input(input("Confirm action by rentering password!"))
                passed = password.encode('UTF-8')
                while ph.hash(passed, salt=salt) != passy:
                    password = sanitise_input(input("Please retry the password"))
                    passed = password.encode('UTF-8')
                load_dotenv(os.path.expanduser(".env"))
                keys = base64.b64decode(os.getenv(f"{username}"))
                addressed = encrypt_customers(keys, addressupdate, salt)
                emil = encrypt_customers(keys, emailed, salt)
                post = encrypt_customers(keys, posty, salt)
                national = encrypt_customers(keys, nation, salt)
                nam = encrypt_customers(keys, named, salt)
                update = {
                "$set": {
                    "fullname": f"{nam}",
                    "email": f"{emil}",
                    "postcode": f"{post}",
                    "country": f"{national}",
                    "address": f"{addressed}"
                }
                }
                upa = db.ClientAccounts.update_one(exists, update)
                if upa:
                    set_env(username, keys)
                    system_logger.warning(f"Account {username} details have been modified.") 
                    print("Details updated!")
                    time.sleep(5)
                    account_info(username, userhash)
                else:
                    print("Didnt insert due to an error, returning to account menu")
                    account_menu(username, userhash)
    else:
        print("Authentication mechanism failed or user not found please relog")
        time.sleep(5)
        system_logger.info(f"{username} has logged out")
        exit()

def complete_transactions(username, userhash):
    print("In this part you will observe and make transactions on behalf of clients, confirming details of them before funds are added and removed")
    hi = sanitise_input(input("Enter what you want to do in this instance \n"
    "1 - Approve a transaction in your group \n"
    "2 - Cancel a transaction in your group (delete the transaction) \n"
    "3 - Return to main menu"))
    db = get_db()
    find = db.ClientAccounts.find_one({"username": f"{username}"}, {"role": 1, "group": 1}) #check validator is a member of the group, advisor can only approve transactions that theya advise on so no conflict of interest
    try:
        if validate(username, userhash) and find.get('role') in ["Financial Advisor", "System Admin"]:
            match hi:
                case "1":
                    system_logger.info(f"{username} has started observing transactions to approve for their group.")
                    translist = list(db.Transactions.find({}))
                    groupies = list(db.CompanyPortfolios.find({"company_name": find.get('group')}, {"members": 1}))
                    narrowed = []
                    for transaction in translist:
                        for groupie in groupies:
                            members = groupie.get('members', [])
                            if transaction['initiated_by'] in members and transaction['approved'] == False:
                                narrowed.append(transaction)#all of this just works - todd howard
                    for thing in narrowed:
                        silly = db.ClientAccounts.find_one({"username": thing['initiated_by']}, {"salt": 1})
                        salty = silly["salt"]
                        amount = decrypt_customers(thing['initiated_by'], thing['amount'], salty)
                        sender_group = decrypt_customers(thing['initiated_by'], thing['sender_group'], salty)
                        print(f" Transaction: {thing['initiated_by']}, {thing['timestamp']}, Sent to: {sender_group} Amount: {amount}")
                    print("Unapproved transactions for your group ^")
                    selection = sanitise_input(input("Please enter the transaction you want to approve in the order presented to you in they printing, starting at 0, 1,2,3 etc."))
                    itemize = narrowed[int(selection)]
                    getsalt = db.ClientAccounts.find_one({"username": itemize['initiated_by']})
                    signature = decrypt_customers(itemize['initiated_by'], itemize['signature'], getsalt['salt'])
                    newsig = bytes.fromhex(signature)
                    userhash = getsalt.get('userhash')
                    theuserskey = itemize['initiated_by']
                    salt = db.ClientAccounts.find_one({"username": theuserskey}, {"salt": 1})
                    with open(f"{theuserskey}pubkey.pem", "rb") as f:
                        line = f.read()
                    retrieval = decrypt_customers(theuserskey, line, salt.get('salt'))
                    print(retrieval)
                    private_key = ECC.import_key(retrieval)
                    newkey = private_key.export_key(format="PEM")
                    other_key = serialization.load_pem_public_key(
                    newkey.encode('utf-8'),
                    )
                    mortodella = other_key.verify(
                    newsig,
                    str(itemize['initiated_by']).encode(),
                    ec.ECDSA(hashes.SHA512())
                    )
                    system_logger.info(f"Signature for transaction verified")
                    if itemize['initiated_by'] in members:
                        send = db.CompanyPortfolios.find_one({"company_name": sender_group})
                        lose = db.CompanyPortfolios.find_one({"company_name": find.get('group')})
                        transactionfun = db.Transactions.find_one({"signature": itemize['signature']})
                        file1 = {
                        "$set":{
                            "approved": True,
                            "approved_by": username
                            }
                        }
                        db.CompanyPortfolios.update_one(
                        send,
                        {"$inc": {"balance": float(amount)}}  # Incrementing the balance
                        )
                        db.CompanyPortfolios.update_one(
                        lose,
                        {"$inc": {"balance": -float(amount)}}  
                        )
                        db.Transactions.update_one(transactionfun, file1)
                        system_logger.info(f"{username} has approved {itemize['initiated_by']}s transaction to {sender_group}")
                        print("Transaction approved, thank you admin returning to the menu for this task now.")
                        time.sleep(5)
                        narrowed.clear()
                        complete_transactions(username, userhash)
                    else:
                        print("the person who initiated this transaction is not in the group, please contact the admin for assistance")
                        system_logger.debug(f"{username} failed to approve transaction due to an error")
                case "2":
                    system_logger.info(f"{username} has started observing transactions to approve for their group.")
                    translist = list(db.Transactions.find({}))
                    groupies = list(db.CompanyPortfolios.find({"company_name": find.get('group')}, {"members": 1}))
                    narrowed = []
                    for transaction in translist:
                        for groupie in groupies:
                            members = groupie.get('members', [])
                            if transaction['initiated_by'] in members and transaction['approved'] == False:
                                narrowed.append(transaction)#all of this just works - todd howard
                    for thing in narrowed:
                        silly = db.ClientAccounts.find_one({"username": thing['initiated_by']}, {"salt": 1})
                        salty = silly["salt"]
                        amount = decrypt_customers(thing['initiated_by'], thing['amount'], salty)
                        sender_group = decrypt_customers(thing['initiated_by'], thing['sender_group'], salty)
                        print(f" Transaction: {thing['initiated_by']}, {thing['timestamp']}, Sent to: {sender_group} Amount: {amount}")
                    print("Unapproved transactions for your group ^")
                    selection = sanitise_input(input("Please enter the transaction you want to DELETE in the order presented to you in they printing, starting at 0, 1,2,3 etc."))
                    itemize = narrowed[int(selection)]
                    transactionfun = db.Transactions.find_one({"signature": itemize['signature']})
                    merde = db.Transactions.delete_one(transactionfun)
                    if merde:
                        narrowed.clear()
                        print(f"Unnaproved transaction deleted for {itemize['initiated_by']}")
                        system_logger.warning(f"{username} deleted an unnaproved transaction by {itemize['initiated_by']}")
                        complete_transactions(username, userhash)
                case "3":
                    account_menu(username, userhash)
                case _:
                    account_menu(username, userhash)
    except Exception as e:
        print("signature validation failed here, illegitimate transaction detected, please contact support to investigate")
        system_logger.warning(f"Signature for {itemize['initiated_by']}s transaction has failed, investigate!")
        print(traceback.print_exc())
        time.sleep(5)
        complete_transactions(username, userhash)
    
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
            system_logger.info(f"account attempt for {username} had too weak a password")
    fa = input("Do you wish to enable 2fa? Y for Yes and N for NO, this uses google authenticator only").upper()
    match fa:
        case "Y":
            secret_token = pyotp.random_base32()
            salty = generate_salt().encode()
            passed = password.encode('UTF-8')
            userhash = ph.hash(username2, salt=salty) #argon2 hash for security
            db = get_db()
            check = db.ClientAccounts.find_one({"username": username})
            if not check:
                keys = keygen(password, salty)
                encemail = encrypt_customers(keys, email, salty)
                encaddress = encrypt_customers(keys, address, salty)
                encname = encrypt_customers(keys, name, salty)
                encpostcode = encrypt_customers(keys, postcode, salty)
                encountry = encrypt_customers(keys, country, salty)
                enc_token = encrypt_customers(keys, secret_token, salty)
                hash = ph.hash(passed, salt=salty)
                file = {
                        "username": f"{username}",
                        "password": f"{hash}",
                        "email": f"{encemail}",
                        "postcode": f"{encpostcode}",
                        "createdat": f"{datetime.now()}",
                        "address": f"{encaddress}",
                        "country": f"{encountry}",
                        "fullname": f"{encname}",
                        "role": "Client",
                        "salt": f"{salty.decode()}",
                        "token": f"{enc_token}",
                        "userhash": f"{userhash}",
                        "group": "none"
                }
                insert = db.ClientAccounts.insert_one(file)
                if insert:
                    totp_auth = pyotp.totp.TOTP(secret_token).provisioning_uri( 
                    name=username, issuer_name='MyFinance')   
                    #generate a new TOTP for 2fa authentication being used for this user
                    qr = qrcode.QRCode(version=1, box_size=2, border=1)  
                    qr.add_data(totp_auth)
                    qr.make()
                    print("Please scan the below code to get setup with google authenticator, add a new authenticator option selected")
                    qr.print_ascii() #get the qr code used to link the user to a 2fa secret via google authenticator
                    system_logger.info(f"Account {username} created with 2fa enabled.") 
                    set_env(username, keys)
                    keyskeyskeys(userhash, salty, keys, username)
                    open_connection()
            else:
                print("Didn't register as the username is already taken please retry.")
                register()

                
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
                    "userhash": f"{userhash}",
                    "group": "none"

            }
            insert = db.ClientAccounts.insert_one(file)
            if insert:
                system_logger.info(f"Account {username} created without 2fa") 
                set_env(username, keys)
                keyskeyskeys(userhash, salty, keys, username)
                open_connection()
            else:
                print("Didnt insert due to an error, please retry")
                register()
        case _: 
            while fa is not "y".upper() or "n".upper():
                print("Please enter Y or N no other inputs please")
                fa = input("Do you wish to enable 2fa? Y for Yes and N for NO").upper()

def user_management(username, userhash):
    admininput = sanitise_input(input("Please enter the admin action for account management you want to do! \n"
    "1 - Register a new portfolio group \n"
    "2 - Change a users role \n"
    "3 - Delete a user \n"
    "4 - Add a user to a portfolio group \n"
    "5 - Manage cryptographic systems \n"
    "6 - Return to account menu \n"))
    system_logger.warning(f"{username} accessed the user management portal")
    token = os.getenv("JWT_CLAIM")
    db = get_db()
    salt = db.ClientAccounts.find_one({"username": username}, {"salt": 1})
    with open(f"{username}pubkey.pem", "rb") as f:
        line = f.read()
    retrieval = decrypt_customers(username, line, salt.get('salt'))
    public_key = ECC.import_key(retrieval)
    newkey = public_key.export_key(format="PEM")
    try:
        jamack = jwt.decode(token, key=newkey, options={"require": ["exp", "iss", "role"]}, algorithms=['ES512',])
        if jamack:
            if admin_check(username) and jamack['role'] == "System Admin":
                match admininput:
                    case "1":
                        print("Creating a new portfolio group....")
                        group_name = sanitise_input(input("Please enter a group name"))
                        balance = sanitise_no(input("Please enter a starting balance"))
                        members = []
                        woah = sanitise_input((input("Enter how many CLIENT MEMBERS (NOT ADVISORS) you want to add to this group by saying their username")))
                        cool = sanitise_input((input("Enter the username of the advisor assigned to this clientelle"))) 
                        found = db.ClientAccounts.find_one({"username": f"{cool}"}, {"role": 1})
                        while found.get("role") not in ["Financial Advisor"]:
                            cool = sanitise_input((input("Enter the username of the advisor assigned to this clientelle, previous entry was not an advisor"))) 
                            found = db.ClientAccounts.find_one({"username": f"{cool}"}, {"role": 1})
                        for i in range(0, int(woah)):
                            getname = sanitise_input(input("Enter a client username"))
                            members.append(getname)
                        file = {
                            "company_name": f"{group_name}",
                            "portfolio_balance": float(balance),
                            "members": members,
                            "advisor": f"{cool}",
                            "investments": []
                        }
                        file2 = {
                            "$set": {
                            "group": f"{group_name}",
                            }
                        }
                        set = db.ClientAccounts.update_one(found, file2)
                        for name in members:
                            one = db.ClientAccounts.find_one({"username": f"{username}"})
                            db.ClientAccounts.update_one(one, file2)
                        entered = db.CompanyPortfolios.insert_one(file)
                        if entered and set:
                            print(f"New portfolio group {group_name} with {members} as members and the advisor being {cool}")
                            system_logger.info(f"New portfolio group {group_name} with {members} as members and the advisor being {cool}")
                            print("Returning to management menu!") 
                            user_management(username, userhash)
                        else:
                            print("Failed to insert due to some error, please renter details again")
                            time.sleep(5)
                            user_management(username, userhash)

                    case "2":
                        userinput = sanitise_input(input("Enter the username you wish to change the role for"))
                        found = db.ClientAccounts.find_one({"username": userinput})
                        while not found:
                            userinput = sanitise_input(input("Previous username not found, please renter"))
                            found = db.ClientAccounts.find_one({"username": userinput})
                        role = sanitise_input(input("Enter role you want to change the user to.  \n"
                        "('Financial Advisor', 'System Admin' and 'Client' are your options)"))
                        update = {
                            "$set": {
                            "role": f"{role}",
                            }
                        }
                        insertion = db.ClientAccounts.update_one(found, update)
                        if insertion:
                            system_logger.critical(f"{userinput} user was updated to {role} by adminsitrator {jamack['username']}")
                            print("User updated to new role permissions! Returning to management menu.")
                            time.sleep(5)
                            user_management(username, userhash)
                        else:
                            print("Unexpected error occured, please retry.")
                            time.sleep(5)
                            user_management(username, userhash)
                    case "3":
                        userinput = sanitise_input(input("Enter the username you to DELETE permenantly from the system"))
                        found = db.ClientAccounts.find_one({"username": userinput})
                        while not found:
                            userinput = sanitise_input(input("Previous username not found, please renter"))
                            found = db.ClientAccounts.find_one({"username": userinput})
                        db.ClientAccounts.delete_one(found)
                        os.remove(f"{userinput}privkey.pem") 
                        os.remove(f"{userinput}pubkey.pem")  
                        system_logger.critical(f"Account {userinput} and respective cryptographic keys have been removed from the system!")
                        print("Account deletion completed, returning to management menu")
                        time.sleep(5)
                        user_management(username, userhash)
                    case "4":
                        putty = sanitise_input(input("enter the name of the USER you want to add"))
                        group = sanitise_input(input("enter the name of the group you want to add the user to"))
                        check1 = db.CompanyPortfolios.find_one({"company_name": group})
                        check2 = db.ClientAccounts.find_one({"username": putty}, {"role": 1})
                        if check2.get("role") in ["System Admin"]:
                            issue = sanitise_input(input("Add this user as a member of the group? (This will overwrite any other advisors)\n"
                            "1 - Yes. \n"
                            "2 - No \n"))
                            match issue:
                                case "1":
                                    file = {
                                    '$set': {
                                    "advisor": putty,
                                    }
                                    }
                                    file2 = {
                                        "$set": {
                                        "group": check1
                                        }
                                    }
                                    db.CompanyPortfolios.update_one(check1, file)
                                    db.ClientAccounts.update_one(check2, file2)
                                    print(f"New advisor {putty} added to the group specified, they can now approve and manage transactions coming in from the clients. Returning to user menu")
                                    system_logger.info(f"New advisor {putty} added to {group}")
                                    time.sleep(5)
                                    user_management(username, userhash)
                                case "2":
                                    print("In this case please restart, advisors are not allowed to profit from businesses.")
                                    time.sleep(5)
                                    user_management(username, userhash)
                                case _:
                                    print("In this case please restart, advisors are not allowed to profit from businesses.")
                                    time.sleep(5)
                                    user_management(username, userhash)
                        else:
                            while not check1 and check2:
                                putty = sanitise_input(input("Previous user or group invalid, enter these again. Please enter the user again."))
                                group = sanitise_input(input("Previous user or group invalid, enter these again. Please enter the group again."))
                            array = check1.get("members")
                            listed = list(array)
                            setcheck = set(listed)
                            existence = putty in setcheck
                            if existence == False:
                                listed.append(putty)
                                file = {
                                "$set": {
                                "members": listed,
                                }
                                }
                                file2 = {
                                "$set": {
                                "group": group
                                }
                                }
                                is1 = db.ClientAccounts.update_one(check2, file2)
                                is2 = db.CompanyPortfolios.update_one(check1, file)
                                if is1 and is2:
                                    system_logger.info(f"{jamack['username']} updated the grouping of user {putty} to the group {group} and can now access their portfolio.")
                                    print("Group updated with new user information, if a group was previously given to a user this has now been overwritten!")
                                    user_management(username, userhash)
                            else:
                                print("This user is already part of this portfolio group for transactions, please restart")

                                user_management(username, userhash)
                    case "5":
                        userlist = list(db.ClientAccounts.find({}))
                        for name in userlist:
                            if os.path.isfile(f"{name['username']}privkey.pem") and os.path.isfile(f"{name['username']}pubkey.pem"):
                                print(f"{name['username']} exists on the system and has both a private and public key present in the system and is encrypted for secure storage. This key pair has been active for {os.path.getmtime(f'{name['username']}privkey.pem')} and was last used on the system at {os.path.getatime(f'{name['username']}privkey.pem')} \n")
                            else:
                                print(f"ERROR! {name['username']} has a missing key value pair and needs revocation/resetting  \n")
                        jorg = sanitise_input(input("Do you want to revoke and refresh keys (1) or go back to the management menu (2). WARNING REFRESHING WILL DELETE ANY UNAPPROVED TRANSACTIONS FROM THE USER!"))
                        match jorg:
                            case "1":
                                system_logger.critical(f"Key revocation is being performed by {username} on {jorg}s account!")
                                andre = sanitise_input(input("Enter the username of the account you want to revoke/refresh keys for.")) #ok this seems weird but my logic is that if that someone malicious is using the keys and we invalidate the user of those keys by a user we can prevent unauthd transactions that havent been checked 
                                find1 = list(db.ClientAccounts.find({"username": andre}))
                                transactionsfromuser = list(db.Transactions.find({}))
                                if find1:
                                     print("Starting...")
                                     firsre = find1[0]
                                     salter = str(firsre['salt']).encode()
                                     decpost = decrypt_customers(andre, firsre['postcode'], salter)
                                     decname = decrypt_customers(andre, firsre['fullname'], salter)
                                     decaddress = decrypt_customers(andre, firsre['address'], salter)
                                     decemail = decrypt_customers(andre, firsre['email'], salter)
                                     decountry = decrypt_customers(andre, firsre['country'], salter)
                                     newsymm = keygen(andre, salter)
                                     with open(".env", "r") as file:
                                        lines = file.readlines()
                                     with open(".env", "w") as file:
                                        for line in lines:
                                            if not line.startswith(f"{andre}="): 
                                                file.write(line)
                                     set_env(andre, newsymm)
                                     encpost = encrypt_customers(newsymm, decpost, salter)
                                     encmail = encrypt_customers(newsymm, decemail, salter)
                                     encaddress = encrypt_customers(newsymm, decaddress, salter)
                                     encname = encrypt_customers(newsymm, decname, salter)
                                     encountry = encrypt_customers(newsymm, decountry, salter)
                                     for trans in transactionsfromuser:
                                         if trans['initiated_by'] == andre and trans['approved'] == False:
                                             db.Transactions.delete_one(trans)
                                     ph = PasswordHasher()
                                     userhash = ph.hash(andre, salt=salter)
                                     keyskeyskeys(userhash, salter, newsymm, andre)
                                     print(f"New keys for user {andre} have been set up and written to files, unapproved transactions deleted and will need to be redone.")
                                     system_logger.warning(f"New keys for user {andre} have been set up and written to files, unapproved transactions deleted and will need to be redone.")
                                     update = {
                                        "$set": {
                                            "fullname": f"{encname}",
                                            "email": f"{encmail}",
                                            "postcode": f"{encpost}",
                                            "country": f"{encountry}",
                                            "address": f"{encaddress}"
                                        }
                                     }
                                     find2 = db.ClientAccounts.find_one({"username": andre})
                                     super = db.ClientAccounts.update_one(find2, update)
                                     if super:
                                         system_logger.critical(f"Key revocation and refreshment of {jorg}s keys has been completed")
                                         print("All updated and set to standard, contact the user to let them know of the refresh via the chat service, returning to menu now!")
                                         user_management(username, userhash)
                                     else:
                                        print("unexpected sigma")
                                else:
                                    print("that user isnt fond, please try again!")
                                    system_logger.critical(f"{username} attempted to revoke keys for a user that didn't exist.")
                                    user_management(username, userhash)
                                    
                            case "2":
                                user_management(username, userhash)
                            case _:
                                user_management(username, userhash)

                    case "6":
                        account_menu(username, userhash)
                    case _:
                        user_management(username, userhash)
            else:
                print("Authentication validators failed")
                system_logger.warning(f"{username} authentication was invalidated mid-task in user management")
                time.sleep(5)
                system_logger.info(f"{username} has logged out")
                exit()
        else:
            print("Authentication validators failed")
            system_logger.warning(f"{username} authentication was invalidated mid-task in user management")
            time.sleep(5)
            system_logger.info(f"{username} has logged out")
            exit()
    except Exception as e:
        print("Authentication validators failed")
        system_logger.debug("Unexpected error occured when handling user management tasks.")
        time.sleep(5)
        system_logger.info(f"{username} has logged out")
        exit()

def open_connection():
    welcome = input("Welcome to the MyFinance Cryptosystem! Please select one of the following options to begin \n"
    "1 - Register a new account \n"
    "2 - Login to the system \n"
    "3 - Exit \n")
    system_logger.info(f"System started...")
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

def security_panel(username, userhash):
    welcome = input("Welcome system admin, please select an option for what you would like to do. If you want to delete a user please go to user management \n"
                "1 - View system and chat logs \n"
                "2 - Apply and review security patches. \n"
                "3 - Return to menu \n")
    match welcome: #system requires python 3.10 or higher pls install
        case "1":
            date_pattern = r'\d{4}-\d{2}-\d{2}'
            today = datetime.now().date()
            with open("chat.log", 'r') as f:
                liner = f.readlines()
            with open("system.log", 'r') as fr:
                lino = fr.readlines()
            print("Critical or warning logs for your attention within the last week!")
            for line in lino:
                if 'WARNING' in line:
                    if today - datetime.strptime(re.findall(date_pattern, line)[0], '%Y-%m-%d').date() < timedelta(weeks = 1):
                        print(f"{line} \n")
                    else:
                        continue
                else:
                    continue
            sar = sanitise_input(input("Would you like to see the full history of logs on the system (THIS MAY BE A LOT OF TEXT AT ONCE), 1 - Yes, 2 - No"))
            match sar:
                case "1":
                    print("CHAT LOG HISTORY:")
                    for log in liner:
                        print(f"{log} \n")
                    print("----------------------------------------------------------------")
                    print("SYSTEM LOG HISTORY:")
                    for lin in lino:
                        print(f"{lin} \n")
                    print("----------------------------------------------------------------")
                    time.sleep(10)
                    system_logger.info(f"Admin {username} viewed all logs")
                    returner = input("Press any key to continue")
                    security_panel(username, userhash)
                case "2":
                    security_panel(username, userhash)
                case _:
                    security_panel(username, userhash)


        case "2":
            result = subprocess.run(["pip", "list", "--outdated"], capture_output=True, text=True)
            print(f"{result.stdout} needs updating!")
            inp = sanitise_input(input("Upgrade updated packagaes now? (Yes/No)"))  
            if inp == "yes" or "Yes" or "YES":
                print(f"{result.stdout} \n"
                      "PACKAGES HAVE BEEN UPGRADED! (but not really)")  #simulation cause that was what you said was allowed!
                system_logger.info(f"{username} upgraded systems packages")
                security_panel(username, userhash)
            else:
                security_panel(username, userhash)
        case "3":
            account_menu(username, userhash)

def account_menu(username, userhash):
    token = os.getenv("JWT_CLAIM")
    db = get_db()
    salt = db.ClientAccounts.find_one({"username": username}, {"salt": 1})
    with open(f"{username}pubkey.pem", "rb") as f:
        line = f.read()
    retrieval = decrypt_customers(username, line, salt.get('salt'))
    public_key = ECC.import_key(retrieval)
    newkey = public_key.export_key(format="PEM")
    try:
        jamack = jwt.decode(token, key=newkey, options={"require": ["exp", "iss", "role"]}, algorithms=['ES512',])
        if jamack:
            if admin_check(username) and jamack['role'] == "System Admin":
                system_logger.critical(f"{username} has accessed the menu of role {jamack['role']}")
                welcome = input("Welcome system admin, please select an option for what you would like to do \n"
                "1 - Make a transaction on behalf of a client \n"
                "2 - View/Modify personal account details \n"
                "3 - Manage user accounts and cryptographic information \n"
                "4 - Send a message to other client and advisors \n"
                "5 - Access security panel including key management, security patching and logs. \n")

                match welcome: #system requires python 3.10 or higher pls install
                    case "1":
                        complete_transactions(username, userhash)
                    case "2":
                        account_info(jamack['username'], userhash)
                    case "3":
                        user_management(jamack['username'], userhash)
                    case "4":
                        chat_service(jamack['username'], userhash)
                    case "5":
                        security_panel(jamack['username'], userhash)
                    case _:
                        os.environ["JWT_CLAIM"] == None
                        print("Exiting command line now!")
                        pass
            elif advisor_check(username) and jamack['role'] == "Financial Advisor": 
                system_logger.critical(f"{username} has accessed the menu of role {jamack['role']}")
                welcome = input("Welcome financial advisor, please select an option for what you would like to do \n"
                "1 - Make a transaction on behalf of a client\n"
                "2 - View/Modify personal account details and view transaction history\n"
                "3 - Send a message to other clients and advisors \n"
                "4 - Logout \n")

                match welcome: #system requires python 3.10 or higher pls install
                    case "1":
                        complete_transactions(username, userhash)
                    case "2":
                        account_info(jamack['username'], userhash)
                    case "3":
                        chat_service(jamack['username'], userhash)
                    case "4":
                        system_logger.info(f"{username} has logged out")
                        os.environ["JWT_CLAIM"] == None
                        print("Logging out and returning to main menu")
                        open_connection()
                    case _:
                        system_logger.info(f"{username} has logged out")
                        os.environ["JWT_CLAIM"] == None
                        print("Exiting command line now!")
                        pass
            else:
                welcome = input("Welcome client member, please select an option for what you would like to do \n"
                "1 - Initiate transaction\n"
                "2 - View/Modify personal account details and view transaction history of you and your groups \n"
                "3 - Send a message to other clients and advisors \n"
                "4 - Logout \n")

                match welcome: #system requires python 3.10 or higher pls install
                    case "1":
                        initate_transaction(jamack['username'], userhash)
                    case "2":
                        account_info(jamack['username'], userhash)
                    case "3":
                        chat_service(jamack['username'], userhash)
                    case "4":
                        os.environ["JWT_CLAIM"] == None
                        print("Logging out and returning to main menu")
                        system_logger.info(f"{username} has logged out")
                        open_connection()
                    case _:
                        exit()
                        print("Exiting command line now!")
                        system_logger.info(f"{username} has logged out")
                        pass
        else:
            print("Your access is invalidated, returning you to the login menu...")
            system_logger.info(f"{username}s JWT expired or was invalidated!")
            os.environ["JWT_CLAIM"] is None
            open_connection()
    except Exception as e:
        system_logger.info(f"{username}s JWT expired or was invalidated!")
        print("Your access is invalidated, returning you to the login menu...")
        os.environ["JWT_CLAIM"] is None
        open_connection()

def login():
    print("To login please enter the following details:")
    username = sanitise_input(input("Enter username for your account"))
    password = sanitise_input(input("Please enter your password"))
    ph = PasswordHasher()
    db = get_db()
    exists = db.ClientAccounts.find_one({"username": f"{username}"})
    if exists:
        passy = exists.get("password")
        salty = exists.get("salt")
        token = exists.get("token")
        role = exists.get('role')
        groups = exists.get('group')
        username2 = username.encode('UTF-8')
        passed = password.encode('UTF-8')
        salt = str(salty).encode('UTF-8')
        userhash = ph.hash(username2, salt=salt)
        while ph.hash(passed, salt=salt) != passy:
            password = sanitise_input(input("Please retry the password"))
            passed = password.encode('UTF-8')
            system_logger.warning(f"{username} had a failed password attempt")
        if token != "no":
            tonkatoken = decrypt_customers(username, token, salt)
            onetime = sanitise_input(input("Enter your otp code from your authenticator app"))
            while is_otp_valid(username, tonkatoken, onetime) == False:
                onetime = sanitise_input("Enter your otp code from your authenticator app")
                system_logger.warning(f"{username} had a failed OTP code entry")
            system_logger.info(f"{username} authenticated through 2fa into the system")
            salt = db.ClientAccounts.find_one({"username": username}, {"salt": 1})
            with open(f"{username}privkey.pem", "rb") as f:
                line = f.read()
            salt2 = str(salty).encode('UTF-8')
            retrieval = decrypt_customers(username, line, salt2)
            if retrieval:
                private_key = ECC.import_key(retrieval)
                newkey = private_key.export_key(format="PEM")
                payload = {
                    "username": username,
                    "role": role,
                    "groups": groups,
                    "iss": "MyFinance System",
                    "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=60)
                }
                token = jwt.encode(payload, newkey, algorithm="ES512")
                os.environ["JWT_CLAIM"] = token
                account_menu(username, userhash)
                
            else:
                print("Couldn't authorise the account, returning to menu, contact an admin for support")
                system_logger.debug(f"{username} had a encryption keys error and couldnt get back their information")
                account_menu(username, userhash)
        else:
            system_logger.info(f"{username} authenticated into the system without 2fa")
            salt = db.ClientAccounts.find_one({"username": username}, {"salt": 1})
            with open(f"{username}privkey.pem", "rb") as f:
                line = f.read()
            salt2 = str(salty).encode('UTF-8')
            retrieval = decrypt_customers(username, line, salt2)
            if retrieval:
                private_key = ECC.import_key(retrieval)
                newkey = private_key.export_key(format="PEM")
                payload = {
                    "username": username,
                    "role": role,
                    "groups": groups,
                    "iss": "MyFinance System",
                    "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=15)
                }
                token = jwt.encode(payload, newkey, algorithm="ES512")
                os.environ["JWT_CLAIM"] = token
                account_menu(username, userhash)
            else:
                print("Couldn't authorise the account, returning to menu, contact an admin for support")
                system_logger.debug(f"{username} had a encryption keys error and couldnt get back their information")
                account_menu(username, userhash)
    else:
        print("This username doesn't exist, please log in again")
        open_connection()


def msg_encrypt(msg, key):
    vector = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=vector)
    encrypted_message_byte, tag = cipher.encrypt_and_digest(msg.encode("utf-8"))
    byte = vector + encrypted_message_byte + tag
    encoder = base64.b64encode(byte)
    return encoder.decode('UTF-8')

def msg_decrypt(msg, key):
    msg = base64.b64decode(msg.encode('utf-8'))
    nonce = msg[:12]  # Correct the nonce length to 12 bytes
    ciphertext = msg[12:-16]  # Get the ciphertext (all bytes except the nonce and tag)
    tag = msg[-16:] 
    reverse = AES.new(key, AES.MODE_GCM, nonce=nonce)
    finalword = reverse.decrypt_and_verify(ciphertext, tag)
    return finalword.decode('utf-8')


def chat_service(username, userhash):
    commchoice = sanitise_input(input("Do you want to host (1), connect to a session (2), send the message to the persons inbox like an email (3) or return to the menu (4)"))
    try:
        kdf = functools.partial(HKDF,
                        key_len=32,
                        salt=b'imgettingtheword',
                        hashmod=SHA256,
                        num_keys=2,
                        context=b'key exchange')
        match commchoice:
            case "1":
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.bind(("127.0.0.1", 4444))
                server.listen(5)
                system_logger.warning(f"Chat session started up on port 4444 by {username}")
                ssl2 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl2.load_cert_chain(certfile="certificate.crt", keyfile="private.key")
                secure_socket = ssl2.wrap_socket(server, server_side=True)
                client_conn, _ = secure_socket.accept() 
                server_priv = ECC.generate(curve='p256')
                server_pub = server_priv.public_key()
                client_conn.sendall(server_pub.export_key(format="DER"))
                client_public_key = ECC.import_key(client_conn.recv(1024))
                shared_secret = key_agreement(static_priv=server_priv, static_pub=client_public_key, kdf=kdf)
                encryption_key, _ = shared_secret
                while True:
                    chat_logger.info(f"{username} has joined a chat session as a host!")
                    encrypted_msg = client_conn.recv(1024).decode()
                    if not encrypted_msg:
                        break
                    decrypted_msg = msg_decrypt(encrypted_msg, encryption_key)
                    chat_logger.info(f"{username} recieved: {decrypted_msg}")
                    print(f"{decrypted_msg}")

                    reply = input("Msg: ")
                    if reply.lower() == "exit":
                        client_conn.close()
                        account_menu(username, userhash)
                    else:
                        setmsg = f"{username}: {reply}"
                        chat_logger.info(f"{username} sent: {setmsg}")
                        encrypted_reply = msg_encrypt(setmsg, encryption_key)
                        client_conn.sendall(encrypted_reply.encode())
                client_conn.close()
            case "2":
                client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client1.connect(("127.0.0.1", 4444))
                system_logger.info(f"user {username} has joined the chat session active on 4444")
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_verify_locations("certificate.crt")  # Verify server certificate
                secure_client = context.wrap_socket(client1, server_hostname="127.0.0.1")
                client_priv = ECC.generate(curve='p256')
                client_pub = client_priv.public_key()
                server_public_key = ECC.import_key(secure_client.recv(1024))
                secure_client.sendall(client_pub.export_key(format="DER"))
                shared_secret = key_agreement(static_priv=client_priv, static_pub=server_public_key, kdf=kdf)
                encryption_key, _ = shared_secret
                while True:
                    chat_logger.info(f"{username} has joined a chat session as a client!")
                    msg = input("You: ")
                    if msg.lower() == "exit":
                        secure_client.close()
                        account_menu(username, userhash)
                    else:
                        setmsg = f"{username}: {msg}"
                        chat_logger.info(f"{username} sent: {setmsg}")
                        encrypted_reply = msg_encrypt(setmsg, encryption_key)
                        secure_client.sendall(encrypted_reply.encode())

                        encrypted_reply = secure_client.recv(1024).decode()
                        decrypted_reply = msg_decrypt(encrypted_reply, encryption_key)
                        chat_logger.info(f"{username} recieved: {decrypted_msg}")
                        print(f"{decrypted_reply}")
                secure_client.close()
            case "3":
                pass
            case "4":
                pass
            case _:
                print("invalid option restart")
                chat_service(username, userhash)

    except Exception as e:
        secure_socket.close()
        server.close()
        print("Communication error occured please retry")
        account_menu(username, userhash)

def encrypt_logs():
    key = Fernet.generate_key()
    with open('system.key', 'wb') as filekey:
      filekey.write(key)
    fernet = Fernet(key)
    for file in ['chat.log', 'system.log']:
        with open(file, 'rb') as reader:
            msg = reader.read()

        encrypted = fernet.encrypt(msg)

    #opneing file in write mode and writing the encrypted data
        with open(file, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)

    


atexit.register(encrypt_logs)

if __name__ == "__main__":
    load_dotenv(verbose=False) 
    open_connection()