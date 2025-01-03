import datetime
import json
import base64
import os
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from messages import Message
from cryptography.hazmat.primitives import hashes, hmac
from Certificate_FASA import All_Certificates


class Server():

    def __init__(self):
        self.message = Message(self)
        server_dir = os.path.join('keys', "Server")
        """Primera instanciacion del servidor. Creamos localizacion de clave
        para desencriptar los jsones y creamos los jsones encriptados"""
        if not os.path.isdir(server_dir):
            os.makedirs(server_dir, exist_ok=True)
            self.create_pepe_keys(server_dir)
            self.create_key(server_dir)
            self.__key = self.get_key(server_dir)
            self.create_jsones()

        self.__key = self.get_key(server_dir)
        self.certificates = self.create_certificates()

    def check_username(self, username):
        data = self.open_and_return_jsons('jsones/users.json')
        for users in data:
            if users['username'] == username:
                return True
        return False

    def check_password(self, username, password):
        users = self.open_and_return_jsons('jsones/users.json')
        for user in users:
            if user["username"] == username:
                password = password.encode("utf-8")
                salt = eval(user["id"])
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=480000,
                )

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
                output += str(counter) + ": " + str(product) + "\n"
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
        if input("Is this the product you want? Type Y/N: ") == "Y":
            self.message.send_messages(product, username)

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

    def create_key(self, route):
        key = ChaCha20Poly1305.generate_key()
        key_hash = os.urandom(16)
        h = hmac.HMAC(key_hash, hashes.SHA256())
        h.update(key)
        h = h.finalize()
        signed_hash = self.sign_with_private(h, route + "/Server_private_key.pem")

        signed_hash_1 = signed_hash[0:255]
        signed_hash_2 = signed_hash[255:]
        encrypted_key = self.encrypt_with_public(key + key_hash, route + "/Server_public_key.pem")
        encrypted_sign_1 = self.encrypt_with_public(signed_hash_1, route + "/Server_public_key.pem")
        encrypted_sign_2 = self.encrypt_with_public(signed_hash_2, route + "/Server_public_key.pem")

        with open(route + "/key.bin", 'wb') as key_file:
            key_file.write(encrypted_key + encrypted_sign_1 + encrypted_sign_2)

    def get_key(self, route):
        with open(route + "/key.bin", 'rb') as key_file:
            key_file = key_file.read()
            simetric_hash = self.decrypt_with_private(key_file[0:512], route + "/Server_private_key.pem")
            sign_1 = self.decrypt_with_private(key_file[512:1024], route + "/Server_private_key.pem")
            sign_2 = self.decrypt_with_private(key_file[1024:], route + "/Server_private_key.pem")

            key = simetric_hash[0:-16]
            token = simetric_hash[-16:]

            key_hash = token
            h = hmac.HMAC(key_hash, hashes.SHA256())
            h.update(key)
            h = h.finalize()
            self.verify_with_public(sign_1 + sign_2, h, route + "/Server_public_key.pem")

            return key

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

            users = encrypter.encrypt(nonce, json_str.encode('utf-8'), None)
            file.write(nonce + users)

    def create_certificates(self):
        if not os.path.join('keys', "Authorities"):
            return All_Certificates(False, [])
        else:
            users = self.open_and_return_jsons('jsones/users.json')
            lista = {}
            for user in users:
                lista[user["username"]] = user["country"]
            return All_Certificates(True, lista)

    def open_and_return_jsons(self, route):
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
        with open(route, 'wb') as file:
            str_data = str(data)
            nonce = os.urandom(12)
            encrypter = ChaCha20Poly1305(self.__key)
            users = encrypter.encrypt(nonce, str_data.encode('utf-8'), None)
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
        # print("\n[DEBUG] Decrypting keys with private key method RSA with key length 4096\n")
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
        # print("\n[DEBUG] Encrypting keys with public key method RSA with key length 4096\n")
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
        return encrypter.encrypt(message)

    def decrypt_with_symetric(self, encrypted, symetric_key):
        encrypter = Fernet(symetric_key)
        return encrypter.decrypt(encrypted)

    def return_public_key(self, username):
        with open("keys/" + username + "/" + username + "_public_key.pem", "rb") as f:
            return f.read()

    def return_private_key(self, username):
        with open("keys/" + username + "/" + username + "_private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
            return private_key

    def create_pepe_keys(self, route):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        public_key = private_key.public_key()
        with open(route + "/Server_private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(route + "/Server_public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

    def expedite_certificate(self, username, country):
        if country == "Spain":
            self.certificates.create_certificate_CSSA(username, country)

        else:
            self.certificates.create_certificate_MVSA(username, country)

    def return_chain(self, username):
        chain = []
        current = username

        while current in self.certificates.chain:
            next_value = self.certificates.chain[current]
            chain.append(next_value)

            # Detenemos si el valor actual es igual a la clave actual (autorreferencia)
            if current == next_value:
                break

            # Continuamos con el siguiente valor
            current = next_value

        buyer_chain_first = [username]
        buyer_chain = buyer_chain_first + chain
        buyer_chain = buyer_chain[:-1]
        list_cert = {}
        for element in buyer_chain:
            if element in {"CSSA", "MVSA", "FASA"}:
                with open("keys/" + "Authorities" + "/" + element + "/" + element + "_cert.pem", "rb") as f:
                    list_cert[element] = f.read()
            else:
                with open("keys/" + element + "/" + element + "_cert.pem", "rb") as f:
                    list_cert[element] = f.read()

        return list_cert

    def check_chain(self, chain):
        contador = 0
        lista_index = list(chain.keys())
        maximo = len(chain)
        for i in chain.keys():
            if not self.validate_certificate_time(x509.load_pem_x509_certificate(chain[i])):
                return False
            if contador != maximo - 1:
                with open("keys/Authorities/" + lista_index[contador + 1] + "/" + lista_index[
                    contador + 1] + "_public_key.pem", "rb") as f:
                    public_key = serialization.load_pem_public_key(
                        f.read()
                    )
                if not self.validate_certificate_signature(x509.load_pem_x509_certificate(chain[i]), public_key):
                    return False
            else:
                with open("keys/Authorities/" + lista_index[contador] + "/" + lista_index[contador] + "_public_key.pem",
                          "rb") as f:
                    public_key = serialization.load_pem_public_key(
                        f.read()
                    )
                if not self.validate_certificate_signature(x509.load_pem_x509_certificate(chain[i]), public_key):
                    return False
            contador += 1

    def validate_certificate_time(self, cert):
        now = datetime.datetime.now(datetime.timezone.utc)
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise ValueError("Certificate outside of validity period.")
        return True

    def validate_certificate_signature(self, cert, public_key):
        try:
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return True
        except Exception as e:
            raise ValueError("Certificate signature not valid") from e
