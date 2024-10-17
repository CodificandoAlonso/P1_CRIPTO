import json
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Server():




    def check_username(username):
        with open('jsones/users.json') as users:
            data = json.load(users)
            for user in data:
                if user['username'] == username :
                    return True
            return False
    def check_password(username, password):
        with open('jsones/users.json') as users:
            data = json.load(users)
            for user in data:
                if user["username"] == username:
                    password = password.encode("utf-8")
                    salt = eval(user["id"])
                    print(salt)
                    kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt= salt,
                    iterations=480000,
                    )

                    print(password)
                    print(salt)
                    key = base64.urlsafe_b64encode(kdf.derive(password))
                    prevtoken = eval(user["token"])
                    print(key)
                    print(prevtoken)
                    if key == prevtoken:
                        return True
            return False
        


    def show_products(self, username):
        with open('jsones/products.json') as products:
            try:
                data = json.load(products)
            except json.JSONDecodeError:
                return print("No products available")
            output = ""
            counter = 0
            for product in data:
                if product["seller"] != username:
                    output +=  str(counter) + ": " + str(product) + "\n"
                    counter += 1
                counter += 1
            if len(output) == 0:
                return print("No products available")
        return print(output)
    
    def add_products(self, username):
        with open('jsones/products.json') as products:
            try:
                data = json.load(products)
            except json.JSONDecodeError:
                data = []
            name = input("Enter the name of the product: ")
            price = input("Enter the price of the product: ")
            data.append({"name": name, "price": price, "seller": username})
            with open('jsones/products.json', 'w', encoding='utf-8') as file:
                json.dump(data, file, indent=4)
            return print("Product added")
        
    def buy_products(self, number, username):
        with open('jsones/products.json') as products:
            try:
                data = json.load(products)
            except json.JSONDecodeError:
                print("There are no products to buy")
            product = data[number]
            print(product["seller"], product["name"])
            if input("Is this the product you want? Type Y/N: ")== "Y":
                print("Enviando tu mensaje jueputa")
                self.send_messages(product,username)

    def send_messages(self, product, buyer):
        with open('jsones/m_unread.json') as messages:
            try:
                data = json.load(messages)
            except json.JSONDecodeError:
                data = []
            content = "Hello " + product["seller"] + ", I have seen your product: " + product["name"] + \
            ", and I think the price of: " + product["price"] + " and I want to buy it. My name is " + buyer

            
            
            message = {"Sender": buyer, "Receiver": product["seller"], "message": content}
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
                for message in messages:
                    print("\n" + message["Sender"] + ": " + message["message"])


            
