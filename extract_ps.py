from pathlib import Path
import shutil
import sqlite3 
import json
import win32crypt 
import base64
from Cryptodome.Cipher import AES


def get_sqlite_file(account="Default"):
    sqlite_file = Path(f"./my_data_{account}.sqlite")
    if not sqlite_file.exists():
        ori_sqlite_file = Path(f"~/AppData/Local/Google/Chrome/User Data/{account}/Login Data").expanduser()
        shutil.copy(ori_sqlite_file, sqlite_file)
    return sqlite_file


def get_data_from_sqlite(sqlite_file):
    conn = sqlite3.connect(sqlite_file)
    cursor = conn.cursor()
    select_statment = 'SELECT origin_url, username_value, password_value FROM Logins'
    cursor.execute(select_statment)
    login_data = cursor.fetchall()
    return login_data


def get_master_key():
    state_file = Path("~/AppData/Local/Google/Chrome/User Data/Local State").expanduser()
    with open(state_file, "r", encoding="utf8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]  # removing DPAPI
        master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key


def decrypt_password(encrypt_pwd):
    iv = encrypt_pwd[3:15]
    payload = encrypt_pwd[15:]
    master_key = get_master_key()
    cipher = AES.new(master_key, AES.MODE_GCM, iv)
    decrypt_pass = cipher.decrypt(payload)
    return decrypt_pass[:-16].decode()


def parser_pwd(login_data):
    pwd_dict = {}
    for url, user_name, encrypt_pwd in login_data:
        if encrypt_pwd[0] == 118:
            pwd = decrypt_password(encrypt_pwd)
        else:
            _, pwd = win32crypt.CryptUnprotectData(encrypt_pwd)

        if len(pwd) != 0:
            if isinstance(pwd, str):
                pwd_dict[url] = (user_name, pwd)
            else:
                pwd_dict[url] = (user_name, pwd.decode('utf8'))
    return pwd_dict


def main():
    account_list = []
    chrome_data_dir = Path("~/AppData/Local/Google/Chrome/User Data/").expanduser()
    account_dirs = chrome_data_dir.glob("Profile*")
    for account_dir in account_dirs:
        if account_dir.is_dir():
            account_list.append(account_dir.name)
    for account in account_list:
        print(account)
        sqlite_file = get_sqlite_file(account)
        login_data = get_data_from_sqlite(sqlite_file)
        pwd_dict = parser_pwd(login_data)
        for url, (account, pwd) in pwd_dict.items():
            print(url, account, pwd)
            print("-"*60)


if __name__ == "__main__":
    main()
