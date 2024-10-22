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
            content = "Product: " + product["name"]
            content = input("Write your message: ")
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
                if input("You don't have messages to read. Do you want to see your message history? Type Y/N: ") == "Y":
                    return self.read_messages(username)
                else:
                    return print("Going home page.")
                
            if input("You have " + str(counter) + " new messages. Do you want to read them? Type Y/N: ") == "Y":                
                for message in messages:
                    key = message["key"]
                    f = Fernet(key.encode())
                    decrypted_message = f.decrypt(message["message"].encode())
                    print("\n" + message["Sender"] + ": " + decrypted_message.decode())
                    if input("\nDo you want to respond the message? Type Y/N: ") == "Y":
                        self.respond_message(message)
                self.move_to_read(messages, username)
            

    def move_to_read(self, messages, username):
        with open('jsones/m_read.json') as file:
            try:
                read_data = json.load(file)
            except json.JSONDecodeError:
                read_data = []
            read_data.extend(messages)
            with open('jsones/m_read.json', 'w', encoding='utf-8') as file:
                json.dump(read_data, file, indent=4)
            try:
                with open('jsones/m_unread.json') as file:
                    unread_data = json.load(file)
            except json.JSONDecodeError:    
                return 'Error opening unread messages.'
            new_list = []
            for message in unread_data:
                if message["Receiver"] != username:
                    new_list.append(message)
            unread_data = new_list
            with open('jsones/m_unread.json', 'w', encoding='utf-8') as file:
                json.dump(unread_data, file, indent=4)

    def read_messages(self, username):
        with open('jsones/m_read.json') as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                return("You don't have message in your history.")
            counter = 0
            messages = []
            for message in data:
                if username == message["Receiver"]:
                    counter += 1
                    messages.append(message)
            if counter == 0:
                return print ("You don't have messages in your histoty.")
            counter = 0
            for message in messages:
                key = message["key"]
                f = Fernet(key.encode())
                decrypted_message = f.decrypt(message["message"].encode())
                print("\n" + str(counter) + ": " + message["Sender"] + ": " + decrypted_message.decode())
                counter += 1
            if input("Do you want to respond a message? Type Y/N: ") == "Y":
                message_number = int(input("Type the number of the message you want to respond: "))
                self.respond_message(messages[message_number])

    
    def respond_message(self, message):
        with open('jsones/m_unread.json') as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                data = []
            content = message["Receiver"] + ' has responded: '
            content += input("Write your message: ")
            token = self.f.encrypt(content.encode("utf-8"))
            new_message = {"Sender": message["Receiver"], "Receiver": message["Sender"], "message": token.decode(), "key": self.key.decode()}
            data.append(new_message)
            with open('jsones/m_unread.json', 'w', encoding='utf-8') as file:
                json.dump(data, file, indent=4)