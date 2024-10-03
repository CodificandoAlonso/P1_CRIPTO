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
        


    def show_products(username):
        with open('jsones/products.json') as products:
            try:
                data = json.load(products)
            except json.JSONDecodeError:
                return print("No products available")
            data = json.load(products)
            output = ""
            counter = 0
            for product in data:
                if product["seller"] != username:
                    output +=  str(counter) + ": " + str(product) + "\n"
                    counter += 1
            
        return print(output)
    
    def add_products(username):
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