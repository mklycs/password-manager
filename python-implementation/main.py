from random import randint
from getpass import getpass
from os.path import exists
import hashlib
import pyperclip
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def select(list):
    while True:
        choice = int(input("Choice: "))
        if choice in list: 
            return choice
        else:
            print("Invalid option.")

def generatePassword():
    generatedPassword = ""
    for _ in range(4):
        generatedPassword += chr(randint(65, 90))
    
    temp = 0
    for _ in range(36):
        while 1:
            temp = randint(33, 126)
            if temp != 34 and temp != 39 and temp != 96:
                break
        generatedPassword += chr(temp)
    
    return generatedPassword

def writeIntoFile(text):
    keyfile = open("key.key","w")
    keyfile.write(text)
    keyfile.close()

def encrypt_file(input_file, output_file, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as f:
        plaintext = f.read()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(iv) 
        f.write(encrypted_data)

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        iv = f.read(16)  
        encrypted_data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    with open(output_file, 'wb') as f:
        f.write(plaintext)

def createDatabase():
    sqlite3_database = sqlite3.connect("dec-database.db")
    sqlite3_cursor = sqlite3_database.cursor()
    sqlite3_cursor.execute("CREATE TABLE IF NOT EXISTS Services (ID INTEGER PRIMARY KEY AUTOINCREMENT, Service TEXT NOT NULL, Password TEXT NOT NULL);")
    return sqlite3_database

def insertInto(sqlite3_database, sqlite3_cursor, service, password):
    insert_into = "INSERT INTO Services (Service, Password) VALUES (?, ?);"
    sqlite3_cursor.execute(insert_into, (service, password))
    sqlite3_database.commit()

def updatePassword(sqlite3_database, sqlite3_cursor, id, password):
    update = "UPDATE Services SET Password = ? WHERE ID = ?;"
    sqlite3_cursor.execute(update, (password, id))
    sqlite3_database.commit()

def deleteFrom(sqlite3_database, sqlite3_cursor, id):
    delete_from = "DELETE FROM Services WHERE ID = ?;"
    sqlite3_cursor.execute(delete_from, (id,))
    sqlite3_database.commit()

def displayServices(sqlite3_cursor, print_message):
    sqlite3_cursor.execute("SELECT ID, Service FROM Services;")
    rows = sqlite3_cursor.fetchall()
    max_entries = len(rows)
    
    if max_entries == 0:
        print("No entries found in the database.")
        return 0

    id = []
    print(print_message)
    for row in rows:
        print("{}. {}".format(row[0], row[1]))
        id.append(row[0])

    return id
    
def copyPassword(sqlite3_database):
    sqlite3_cursor = sqlite3_database.cursor()
    print_message = "Enter the numeric value of the service you would like to copy the password to clipboard."
    max_entries = displayServices(sqlite3_cursor, print_message)
    if max_entries == 0: return
    
    choice = select(max_entries)
    sqlite3_cursor.execute("SELECT Password FROM Services WHERE ID = ?;", (choice,))
    rows = sqlite3_cursor.fetchall()
    password = rows[0][0]

    pyperclip.copy(password)
    print("Password copied successfully to clipboard.")

def addService(sqlite3_database):
    sqlite3_cursor = sqlite3_database.cursor()
    service = input("Enter the name of the service you would like to add: ")

    sqlite3_cursor.execute("SELECT Service FROM Services WHERE Service = ?;", (service,))
    if len(sqlite3_cursor.fetchall()) != 0:
        print("A service with this name does already exist with a password in the database.")
        return
    
    password = getpass("Enter password (leave blank if you want to generate a random password): ")
    if len(password) == 0:
        password = generatePassword()
    
    insertInto(sqlite3_database, sqlite3_cursor, service, password)

def changePassword(sqlite3_database):
    sqlite3_cursor = sqlite3_database.cursor()
    print_message = "Enter the numeric value of the service you would like to change the password."
    max_entries = displayServices(sqlite3_cursor, print_message)
    if max_entries == 0: return

    choice = select(max_entries)
    password = getpass("Enter new password (leave blank if you want to generate a random password): ")
    if len(password) == 0:
        password = generatePassword()

    updatePassword(sqlite3_database, sqlite3_cursor, choice, password)

def deleteService(sqlite3_database):
    sqlite3_cursor = sqlite3_database.cursor()
    print_message = "Enter the numeric value of the service you would like to delete."
    max_entries = displayServices(sqlite3_cursor, print_message)
    if max_entries == 0: return
    
    choice = select(max_entries)
    deleteFrom(sqlite3_database, sqlite3_cursor, choice)

def changeMasterpassword():
    masterpassword = getpass("Enter new masterpassword: ")
    masterpassword_repeated = getpass("Repeat masterpassword: ")

    if masterpassword != masterpassword_repeated:
        print("Masterpasswords don't match.")
        return
    
    hashed_masterpassword = hashlib.sha256(masterpassword.encode("utf-8")).digest()
    writeIntoFile(hashed_masterpassword.hex())
    print("The masterpassword was successfully stored in \"key.key\". Restart the program to be able to further use the password manager.")

def main():
    masterpassword = getpass("Enter masterpassword: ")
    hashed_masterpassword = hashlib.sha256(masterpassword.encode("utf-8")).digest()

    if exists("database.db") == True:
        decrypt_file("database.db", "dec-database.db", hashed_masterpassword)

    if exists("key.key") == False:
        masterpassword_repeated = getpass("Repeat masterpassword: ")

        if masterpassword != masterpassword_repeated:
            print("Masterpasswords don't match.")
            return

        writeIntoFile(hashed_masterpassword.hex())
        print("The masterpassword was successfully stored in \"key.key\". Restart the program to be able to further use the password manager.")
        return
    else:
        with open("key.key", "r") as keyfile:
            stored_masterpassword = bytes.fromhex(keyfile.read())
        
        if stored_masterpassword != hashed_masterpassword:
            print("Masterpasswords don't match.")
            return
        
    sqlite3_database = createDatabase()

    while True:
        choice = int(input("Choose an option:\n1. Copy password for a service\n2. Add new service\n3. Change password for a service\n4. Delete a service\n5. Change masterpassword\n6. Exit program\nChoice: "))

        if choice == 1:
            copyPassword(sqlite3_database)
        elif choice == 2:
            addService(sqlite3_database)
        elif choice == 3:
            changePassword(sqlite3_database)
        elif choice == 4:
            deleteService(sqlite3_database)
        elif choice == 5:
            changeMasterpassword()
        elif choice == 6:
            break
        else:
            print("Only option 1-6 available.\n")
    
    sqlite3_database.close()
    encrypt_file("dec-database.db", "database.db", hashed_masterpassword)
    encrypt_file("dec-database.db", "dec-database.db", hashed_masterpassword)
    os.remove("dec-database.db")

if __name__ == "__main__":
    main()
