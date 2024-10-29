from cryptography.fernet import Fernet

import getpass
import json
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidKey


class Message():
    
    def __init__(self, server):
        self.access_server = server
        """self.key = Fernet.generate_key()
        self.f = Fernet(self.key)"""
    def send_messages(self, product, buyer):
        """with open('jsones/m_unread.json') as messages:
            try:
                data = json.load(messages)
            except json.JSONDecodeError:
                data = []"""
        list_messages = self.access_server.open_and_return_jsons('jsones/m_unread.json')
        content = "Product: " + product["name"] + " : "
        content += input("Write your message: ")


        keys = self.access_server.open_and_return_jsons('jsones/simetric_keys.json')
        key = 0
        for participant in keys:
            if participant["Receiver"] == buyer and participant["Sender"] == product["seller"]:
                key = participant["Key"]
        if key == 0:
            key = Fernet.generate_key()
            f = Fernet(key)
        else:
            #BUSCAMOS LA CLAVE PRIVADA DE BUYER
            route = "keys/" + buyer + "/" + buyer + "_private_key.pem"
            """with open(route, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )
            decrypted_key = private_key.decrypt(   #DESENCRIPTAMOS CLAVE SIMETRICA
                key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
                )"""
            decrypted_key = self.access_server.decrypt_with_private(key, route)
            """f = Fernet(decrypted_key)
            token = f.encrypt(content.encode("utf-8"))  #ENCRIPTO MENSAJE"""
            token = self.access_server.encrypt_with_symetric(content.encode("utf-8"), decrypted_key)
            message = {"Sender": buyer, "Receiver": product["seller"], "message": token.decode()}
            list_messages.append(message)
            return self.access_server.save_jsons(list_messages,'jsones/m_unread.json')
            
        
        #Obtenemos la clave publica de product["seller"]
        route_seller = "keys/" + product["seller"] + "/" + product["seller"] + "_public_key.pem"
        #Obtenemos la clave publica de buyer
        """route = "keys/" + buyer + "/" + buyer + "_public_key.pem"
        with open(route, "rb") as key_file:
            public_key_buyer = serialization.load_pem_public_key(key_file.read())"""
        
        #token = f.encrypt(content.encode("utf-8"))  #ENCRIPTO MENSAJE
        token = self.access_server.encrypt_with_symetric(content.encode("utf-8"), key)
        """encrypted_simetric_key = public_key.encrypt(  #ENCRIPTO CLAVE SIMETRICA PARA EL RECEPTOR DEL MENSAJE
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )"""
        encrypted_simetric_key = self.access_server.encrypt_with_public(key, route_seller)
        #COMO ES LA PRIMERA VEZ, ENCRIPTO TMB ESTO CON LA PRIVADA DE BUYER 
        """route = "keys/" + buyer + "/" + buyer + "_private_key.pem"
        with open(route, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )"""
        """
        sign = private_key.sign(
            encrypted_simetric_key,
            padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
                                                ),
            hashes.SHA256()
        )"""
        route_buyer = "keys/" + buyer + "/" + buyer + "_private_key.pem"
        route_buyer_pub = "keys/" + buyer + "/" + buyer + "_public_key.pem"
        sign = self.access_server.sign_with_private(encrypted_simetric_key, route_buyer)


        """encrypted_simetric_key2 = public_key_buyer.encrypt(  #ENCRIPTO CLAVE SIMETRICA2 PARA EL BUYER
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )"""
        encrypted_simetric_key2 = self.access_server.encrypt_with_public(key, route_buyer_pub)
        content_to_save = {"Sender": buyer, "Receiver":product["seller"], "Key": encrypted_simetric_key, "sign" : sign }
        keys.append(content_to_save)
        content_to_save = {"Sender": product["seller"], "Receiver":buyer, "Key": encrypted_simetric_key2, "sign": "" }
        keys.append(content_to_save)
        message = {"Sender": buyer, "Receiver": product["seller"], "message": token.decode()}
        list_messages.append(message)

        self.access_server.save_jsons(keys, "jsones/simetric_keys.json")
        self.access_server.save_jsons(list_messages,'jsones/m_unread.json')


    def check_messages(self, username):
        list_messages = self.access_server.open_and_return_jsons('jsones/m_unread.json')
        if len(list_messages) == 0:
            if input("\nYou don't have messages to read. Do you want to see your message history? Type Y/N: ") == "Y":
                return self.read_messages(username)
            else:
                return print("\nGoing home page.\n")
        counter = 0
        messages = []
        for message in list_messages:
            if username == message["Receiver"]:
                counter += 1
                messages.append(message)
        if counter == 0:
            if input("\nYou don't have messages to read. Do you want to see your message history? Type Y/N: ") == "Y":
                return self.read_messages(username)
            else:
                return print("\nGoing home page.\n")
        
        if input("You have " + str(counter) + " new messages. Do you want to read them? Type Y/N: ") == "Y":                
            #Coger la clave privada del usuario para desencriptar
            route = "keys/" + username + "/" + username + "_private_key.pem"
            with open(route, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
            new_unread = []
            for message in messages:
                encrypted_message = message["message"]
                #Coger la clave simetrica de la conversacion
                conversations = self.access_server.open_and_return_jsons('jsones/simetric_keys.json')
                sign = ""
                for item in conversations:
                    if item["Receiver"] == username and message["Sender"] == item["Sender"]:
                        sim_key_encrypted = item["Key"]
                        if item["sign"] != "":
                            sign = item["sign"]
                if sign == "":
                    sim_key_decrypted = private_key.decrypt(
                    sim_key_encrypted,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                        )
                )
                else:
                    #COJO LA PUBLICA DEL SENDER
                    route = "keys/" + message["Sender"] + "/" + message["Sender"] + "_public_key.pem"
                    with open(route, "rb") as key_file:
                        public_key = serialization.load_pem_public_key(
                        key_file.read()
                    )
                    #VERIFICO
                        public_key.verify(
                            sign,
                            sim_key_encrypted,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                    sim_key_decrypted = private_key.decrypt(
                    sim_key_encrypted,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                        )
                    )

                f = Fernet(sim_key_decrypted)
                token = f.decrypt(encrypted_message.encode("utf-8"))
                print("\n" + message["Sender"] + ": " + token.decode())
                if input("\nDo you want to respond the message? Type Y/N: ") == "Y":
                    self.respond_message(message, username)
                self.move_to_read(token.decode(), message["Sender"],username)
        list_messages = self.access_server.open_and_return_jsons('jsones/m_unread.json')
        for a in list_messages:
            if a not in messages:
                new_unread.append(a)
        self.access_server.save_jsons(new_unread,'jsones/m_unread.json')

        


    def move_to_read(self, message, sender, username):
        #cargamos todo lo que hay
        read_data = self.access_server.open_and_return_jsons('jsones/m_read.json')
        #tenemos que encriptar el mensaje con la clave publica del usuario,
        #como si se enviara a si mismo, para que solo el tenga acceso al historial
        #Coger la clave privada del usuario para desencriptar
        route_usr_pub = "keys/" + username + "/" + username + "_public_key.pem"
        message = message.encode("utf-8")

        """with open(route_usr_pub, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        encrypted_message = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                        )
            )"""
        encrypted_message = self.access_server.encrypt_with_public(message, route_usr_pub)
        to_save = {"Owner": username, "Sender": sender, "message": encrypted_message}
        read_data.append(to_save)
        self.access_server.save_jsons(read_data,'jsones/m_read.json')
        
    def read_messages(self, username):
        #obtengo clave privada de username
        """with open(route_usr_prv, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )"""
        private_key = self.access_server.return_private_key(username)
        messages_list = self.access_server.open_and_return_jsons('jsones/m_read.json')
        if messages_list == []:
            return print("\nYou don't have message in your history.\n")
        messages = []
        counter = 0
        for message in messages_list:
            if username == message["Owner"]:
                counter += 1
                messages.append(message)
        if counter == 0:
            return print ("\nYou don't have messages in your history.\n")
        for message in messages:
            """decrypted_message = private_key.decrypt(
                message["message"],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )"""
            decrypted_message = self.access_server.decrypt_with_private(message["message"], "keys/" + username + "/" + username + "_private_key.pem")
            print("\nMensaje de:", message["Sender"], " :", decrypted_message.decode('utf-8'))

        

    
    def respond_message(self, message, sender):
        list_messages = self.access_server.open_and_return_jsons('jsones/m_unread.json')
        content ="\n" + sender + ' has responded: '
        content += input("Write your message: ")
        keys = self.access_server.open_and_return_jsons('jsones/simetric_keys.json')
        key = 0

        #Coger la clave privada del usuario para desencriptar
        route = "keys/" + sender + "/" + sender + "_private_key.pem"
        """with open(route, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read()
                                                             ,password=None)"""

        for participant in keys:
            if participant["Receiver"] == message["Receiver"] and participant["Sender"] == message["Sender"]:
                key = participant["Key"]

        """symetric_key = private_key.decrypt(   #DESENCRIPTAMOS CLAVE SIMETRICA
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
            )"""
        symetric_key = self.access_server.decrypt_with_private(key, route)
        """f = Fernet(symetric_key)
        token = f.encrypt(content.encode("utf-8"))"""
        token = self.access_server.encrypt_with_symetric(content.encode("utf-8"), symetric_key)
        message = {"Sender": sender, "Receiver": message["Sender"], "message": token.decode()}
        list_messages.append(message)
        self.access_server.save_jsons(list_messages,'jsones/m_unread.json')