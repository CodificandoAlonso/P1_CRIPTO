import json
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from messages import Message


class Server():

    def __init__(self):
        self.message = Message()
        server_dir = os.path.join('keys', "Server")
        """Primera instanciacion del servidor. Creamos localizacion de clave
        para desencriptar los jsones y creamos los jsones encriptados"""  
        if not os.path.isdir(server_dir):
            os.makedirs(server_dir, exist_ok=True)
            self.create_key(server_dir)
            self.__key = self.get_key(server_dir)
            self.create_jsones()
        self.__key = self.get_key(server_dir)
        print(self.__key)


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

    
    def encrypt_and_save_json(data, file_path, key):
        # Convertir el JSON a una cadena
        json_str = json.dumps(data)
        
        # Generar un nonce de 12 bytes
        nonce = os.urandom(12)
        
        # Crear una instancia de ChaCha20Poly1305
        chacha = ChaCha20Poly1305(key)
        
        # Cifrar el contenido JSON
        ciphertext = chacha.encrypt(nonce, json_str.encode('utf-8'), None)
        
        # Guardar el contenido cifrado en un archivo
        with open(file_path, 'wb') as file:
            file.write(nonce + ciphertext)



    def create_key(self,route):
        try:
            with open(route + "/key.bin", 'wb') as key_file:
                key = ChaCha20Poly1305.generate_key()
                key_file.write(key)
        except FileNotFoundError:
            key = ChaCha20Poly1305.generate_key()
            key_file.write(key)

            
    def get_key(self, route):
        with open(route + "/key.bin", 'rb') as key_file:
            return key_file.read()
        


    def create_jsones(self):
        """users    products    m_unread     m_read"""
        encrypter = ChaCha20Poly1305(self.__key)
        self.create_each_json(encrypter, "users.json")
        self.create_each_json(encrypter, "products.json")
        self.create_each_json(encrypter, "m_unread.json")
        self.create_each_json(encrypter, "m_read.json")

    def create_each_json(self, encrypter, route):
        json_route = os.path.join('jsones')
        with open(json_route + "/" + route, 'wb') as file:

            data = []
            json_str = json.dumps(data)
            nonce = os.urandom(12)
            
            users = encrypter.encrypt(nonce,json_str.encode('utf-8'), None)
            file.write(nonce + users)

