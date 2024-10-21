from cryptography.fernet import Fernet

import getpass
import json
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Message():
    
    def __init__(self):
        self.key = Fernet.generate_key()
        self.f = Fernet(self.key)
    def send_messages(self, product, buyer):
        with open('jsones/m_unread.json') as messages:
            try:
                data = json.load(messages)
            except json.JSONDecodeError:
                data = []
            content = "Hello " + product["seller"] + ", I have seen your product: " + product["name"] + \
            ", and I think the price of: " + product["price"] + " and I want to buy it. My name is " + buyer
            
            token = self.f.encrypt(content.encode("utf-8"))
            

            
            
            message = {"Sender": buyer, "Receiver": product["seller"], "message": token.decode(), "key": self.key.decode()}
            data.append(message)
            with open('jsones/m_unread.json', 'w', encoding='utf-8') as file:
                json.dump(data, file, indent=4)

    def check_messages(self, username):
        with open('jsones/m_unread.json') as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                return("You don't have messages to read.")
            counter = 0
            messages = []
            for message in data:
                if username == message["Receiver"]:
                    counter += 1
                    messages.append(message)
            if counter == 0:
                return ("You don't have messages to read.")
            if input("You have " + str(counter) + " new messages. Do you want to read them? Type Y/N: ") == "Y": 
                """for message in messages:
                    print("\n" + message["Sender"] + ": " + message["message"])"""
                
                # Desencriptar el token
                decrypted_message = self.f.decrypt(message)
                print(decrypted_message)

                # Mostrar el mensaje desencriptado
                print("Mensaje desencriptado:", decrypted_message)
                print("Esta es la key: ", self.key)