import json
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from messages import Message


class Server():

    def __init__(self):
        self.message = Message()


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
                    kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt= salt,
                    iterations=480000,
                    )

                    
                    key = base64.urlsafe_b64encode(kdf.derive(password))
                    prevtoken = eval(user["token"])
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
            print(output)
            buy = input("Do you want to buy a product? Type: Y/N: ")
            if buy == "Y":
                number = int(input("Put the product number you want to buy: "))
                self.buy_products(number, username)
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
                self.message.send_messages(product,username)

    


            
