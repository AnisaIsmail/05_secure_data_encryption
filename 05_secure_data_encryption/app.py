import streamlit as st
from crypto_utils import hash_passkey, encrypt_data, decrypt_data
from auth import users, stored_data, authenticate_user, register_user, increment_attempts, reset_attempts, is_locked_out

st.set_page_config(page_title="Secure Data Vault", layout="centered")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "mode" not in st.session_state:
    st.session_state.mode = "Home"

def login_page():
    st.title("🔐 Login Page")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if authenticate_user(username, password):
            st.session_state.logged_in = True
            st.session_state.username = username
            reset_attempts(username)
            st.success("Login successful!")
        else:
            st.error("Invalid credentials")

def home_page():
    st.title("🏠 Secure Data Vault")
    st.write(f"Welcome, **{st.session_state.username}**!")
    st.button("Store New Data", on_click=lambda: st.session_state.update(mode="Insert"))
    st.button("Retrieve Data", on_click=lambda: st.session_state.update(mode="Retrieve"))

def insert_data_page():
    st.title("📥 Store Data")
    text = st.text_area("Enter the text to encrypt")
    passkey = st.text_input("Enter a passkey", type="password")
    if st.button("Encrypt & Store"):
        if text and passkey:
            enc_text = encrypt_data(text, passkey)
            hashed_key = hash_passkey(passkey)
            stored_data[st.session_state.username] = {
                "encrypted_text": enc_text,
                "passkey": hashed_key
            }
            st.success("Data encrypted and stored successfully!")
        else:
            st.warning("Please enter both text and a passkey.")

def retrieve_data_page():
    st.title("📤 Retrieve Data")
    passkey = st.text_input("Enter your passkey", type="password")
    if st.button("Decrypt"):
        user_data = stored_data.get(st.session_state.username)
        if not user_data:
            st.error("No data stored.")
            return
        if is_locked_out(st.session_state.username):
            st.warning("Too many failed attempts. Please re-login.")
            st.session_state.logged_in = False
            return
        hashed_input = hash_passkey(passkey)
        if hashed_input == user_data["passkey"]:
            try:
                decrypted = decrypt_data(user_data["encrypted_text"], passkey)
                st.success("Decryption successful!")
                st.code(decrypted)
                reset_attempts(st.session_state.username)
            except:
                st.error("Error decrypting. Invalid passkey?")
                increment_attempts(st.session_state.username)
        else:
            increment_attempts(st.session_state.username)
            st.error(f"Incorrect passkey.")

def main():
    if not st.session_state.logged_in:
        login_page()
    else:
        if st.session_state.mode == "Home":
            home_page()
        elif st.session_state.mode == "Insert":
            insert_data_page()
            st.button("Back", on_click=lambda: st.session_state.update(mode="Home"))
        elif st.session_state.mode == "Retrieve":
            retrieve_data_page()
            st.button("Back", on_click=lambda: st.session_state.update(mode="Home"))

main()
