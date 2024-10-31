import json
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from messages import Message


class Server():

    def __init__(self):
        self.message = Message(self)
        server_dir = os.path.join('keys', "Server")
        """Primera instanciacion del servidor. Creamos localizacion de clave
        para desencriptar los jsones y creamos los jsones encriptados"""  
        if not os.path.isdir(server_dir):
            os.makedirs(server_dir, exist_ok=True)
            self.create_key(server_dir)
            self.__key = self.get_key(server_dir)
            self.create_jsones()
        self.__key = self.get_key(server_dir)






    def check_username(self,username):
        data = self.open_and_return_jsons('jsones/users.json')      
        for users in data:
            if users['username'] == username :
                    return True
        return False
        

    def check_password(self,username, password):
        users = self.open_and_return_jsons('jsones/users.json')
        for user in users:
            if user["username"] == username:
                password = password.encode("utf-8")
                salt = eval(user["id"])
                kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt= salt,
                iterations=480000,
                )

                print("\n[DEBUG] Encrypting password using PBKDF2HMAC\n")
                key = base64.urlsafe_b64encode(kdf.derive(password))
                prevtoken = eval(user["token"])
                if key == prevtoken:
                    return True
        return False
        


    def show_products(self, username):
        products = self.open_and_return_jsons('jsones/products.json')
        if products == []:
            return print("No products available")
        output = ""
        counter = 0
        for product in products:
            if product["seller"] != username:
                output +=  str(counter) + ": " + str(product) + "\n"
            counter += 1
        if len(output) == 0:
            return print("No products available")
        print(output)
        buy = input("Do you want to buy a product? Type: Y/N: ")
        if buy == "Y":
            number = int(input("Put the product number you want to buy: "))
            self.buy_products(number, username)
    
    def add_products(self, username):
        products = self.open_and_return_jsons('jsones/products.json')
        name = input("Enter the name of the product: ")
        price = input("Enter the price of the product: ")
        products.append({"name": name, "price": price, "seller": username})
        self.save_jsons(products, 'jsones/products.json')
        return print("Product added")
        
    def buy_products(self, number, username):
        products = self.open_and_return_jsons('jsones/products.json')
        product = products[number]
        print(product["seller"], product["name"])
        if input("Is this the product you want? Type Y/N: ")== "Y":
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
        """users    products    m_unread     m_read    simetric_keys"""
        encrypter = ChaCha20Poly1305(self.__key)
        self.create_each_json(encrypter, "users.json")
        self.create_each_json(encrypter, "products.json")
        self.create_each_json(encrypter, "m_unread.json")
        self.create_each_json(encrypter, "m_read.json")
        self.create_each_json(encrypter, "simetric_keys.json")

    def create_each_json(self, encrypter, route):
        json_route = os.path.join('jsones')
        with open(json_route + "/" + route, 'wb') as file:

            data = []
            json_str = json.dumps(data)
            nonce = os.urandom(12)
            
            users = encrypter.encrypt(nonce,json_str.encode('utf-8'), None)
            file.write(nonce + users)



    def open_and_return_jsons(self,route):
        with open(route, 'rb') as file:
            data = file.read()
        nonce = data[:12]
        ciphertext = data[12:]
        
        # Crear una instancia de ChaCha20Poly1305
        chacha = ChaCha20Poly1305(self.__key)
        
        # Descifrar el contenido JSON
        json_str = chacha.decrypt(nonce, ciphertext, None)
        
        # Convertir la cadena JSON a un objeto Python
        return eval(json_str)
    

    def save_jsons(self, data, route):
        with open(route , 'wb') as file:
            str_data = str(data)
            nonce = os.urandom(12)
            encrypter = ChaCha20Poly1305(self.__key)
            users = encrypter.encrypt(nonce,str_data.encode('utf-8'), None)
            file.write(nonce + users)

    def delete_symetric(self):
        encrypter = ChaCha20Poly1305(self.__key)
        self.create_each_json(encrypter, "simetric_keys.json")
        self.create_each_json(encrypter, "m_unread.json")



    def sign_with_private(self, message, private_key_route):
        with open(private_key_route, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    def verify_with_public(self, signature, message, public_key_route):
        with open(public_key_route, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def decrypt_with_private(self, encrypted, private_key_route):
        with open(private_key_route, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        print("\n[DEBUG] Decrypting keys with private key method RSA with key length 4096\n")
        return private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    def encrypt_with_public(self, message, public_key_route):
        with open(public_key_route, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
        print("\n[DEBUG] Encrypting keys with public key method RSA with key length 4096\n")
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def encrypt_with_symetric(self, message, symetric_key):
        encrypter = Fernet(symetric_key)
        print("\n[DEBUG] Encrypting Message with symetric key method Fernet\n")
        return encrypter.encrypt(message)
    
    def decrypt_with_symetric(self, encrypted, symetric_key):
        encrypter = Fernet(symetric_key)
        print("\n[DEBUG] Decrypting Message with symetric key method Fernet\n")
        return encrypter.decrypt(encrypted)
    
    def return_public_key(self, username):
        with open("keys/" + username + "/"+username+"_public_key.pem", "rb") as f:
            return f.read()
        
    def return_private_key(self, username):
        with open("keys/" + username + "/"+username+"_private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
            return private_key