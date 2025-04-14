import streamlit as st
from pbkdf2 import PBKDF2
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode

DATA = "data.json"
SALT = b"secure_value"
LOCKOUT = 60

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
    
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
    
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
    

def load_data() -> None:
    if os.path.exists(DATA):
        with open(DATA, "r") as file:
            return json.load(file)
        
    return {}

def save_data(data: json) -> None:
    with open(DATA, "w") as file:
        json.dump(data, file)
        
        
def gen_key(passkey: str) -> bytes:
    derived_key = PBKDF2(passkey.encode(), SALT).read(32)
    return urlsafe_b64encode(derived_key)

def hash_pass(password: str) -> str:
    derived = PBKDF2(password.encode(), SALT).read(32)
    return urlsafe_b64encode(derived).decode()

def encrypted_text(text, key):
    cipher = Fernet(gen_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypted_text(encrypt_text, key):
    try:
        cipher = Fernet(gen_key(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    
    except:
        return None
    
stored_data = load_data()

st.set_page_config(page_title="Data Encryption")
st.title("Data Encryption")

def home():
    desc = [
        "Users store data with a unique passkey.",
        "Users decrypt data by providing the correct passkey.",
        "Multiple failed attempts result in a forced reauthorization (login page).",
        "The system operates entirely in memory without external databases."
    ]
    st.subheader("Welcome to our Application, Your data is secure with us.\nHere is a little demo:")
    for index, line in enumerate(desc):
        st.write(f"{index+1}. {line}")
        
def register():
    st.subheader("Register yourself now!")
    username = st.text_input("Enter a username:")
    password = st.text_input("Create a password:", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("User already exist!")
                
            else:
                stored_data[username] = {
                    "password": hash_pass(password),
                    "data": []
                }
                save_data(data=stored_data)
                st.success("Registered Successfully.")
        
        else:
            st.error("Both fields are required!")
            

def login():
    st.subheader("Login")
    
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many failed attempts! try again after {LOCKOUT} seconds.")
        st.stop()
        
    username = st.text_input("Enter your username:")
    password = st.text_input("Enter your password:", type="password")
    
    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_pass(password):
           st.session_state.authenticated_user = username
           st.session_state.failed_attempts = 0
           st.success(f"Login Successfully. Welcome {username}")
        
        else:
            st.error("Wrong username or password")
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            
            
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT
                st.error(f"Too many failed attempts! try again after {LOCKOUT} seconds.")
                st.stop()
                
def store_data():
    if not st.session_state.authenticated_user:
        st.warning("Please login first.")
    else:
        st.subheader("Store Encrypted Data Here..")
        data = st.text_area("Enter data to encrypt.")
        passkey = st.text_input("Encryption Key:", type="password")
        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypted_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("Data encrypted and saved.")
                st.write(f"Your passkey is: {passkey}")
            
            else:
                st.error("All fields must be filled!")
                
                
def retrieve_data():
    if not st.session_state.authenticated_user:
        st.warning("Please login first.")
        
    else:
        st.subheader("Retrieve Your Data..")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])
        if not user_data:
            st.info("No data found.")
        
        else:
            st.write("Encrypted Data Enteries:")
            for index, item in enumerate(user_data):
                st.code(f"{index+1}: {item}", language="text")
                
            encrypted_input = st.text_area("Enter encrypted key:")
            passkey = st.text_input("Enter decrypt passkey:", type="password")
            if st.button("Decrypt Data"):
                if encrypted_input and passkey:
                    result = decrypted_text(encrypted_input, passkey)
                    if result:
                        st.success(f"Data Retrieved: {result}")
                    else:
                        st.error("Something went wrong.")
                else:
                    st.error("Incorrect passkey or corrupted data.")
                


menu = ["Home", "Store Data", "Retrieve Data", "Register", "Login"]

choice = st.sidebar.selectbox("Navigation", menu, placeholder="Home")





if choice == "Home":
    home()
    
elif choice == "Register":
    register()
    
elif choice == "Login":
    login()
    
elif choice == "Store Data":
    store_data()
    
elif choice == "Retrieve Data":
    retrieve_data()

