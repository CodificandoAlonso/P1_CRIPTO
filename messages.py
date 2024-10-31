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

    def send_messages(self, product, buyer):
        list_messages = self.access_server.open_and_return_jsons('jsones/m_unread.json')
        content = "Product: " + product["name"] + " : "
        content += input("Write your message: ")


        keys = self.access_server.open_and_return_jsons('jsones/simetric_keys.json')
        key = 0
        for participant in keys:
            if participant["Receiver"] == buyer and participant["Sender"] == product["seller"]:
                key = participant["Key"]
        if key == 0: #NO COMUNICACION
            key = Fernet.generate_key()
            f = Fernet(key)
        else:
            #BUSCAMOS LA CLAVE PRIVADA DE BUYER
            route = "keys/" + buyer + "/" + buyer + "_private_key.pem"
            #DESENCRIPTAMOS LA CLAVE SIMETRICA
            decrypted_key = self.access_server.decrypt_with_private(key, route)
            #ENCRIPTAMOS EL MENSAJE
            token = self.access_server.encrypt_with_symetric(content.encode("utf-8"), decrypted_key)
            message = {"Sender": buyer, "Receiver": product["seller"], "message": token.decode()}
            list_messages.append(message)
            return self.access_server.save_jsons(list_messages,'jsones/m_unread.json')
            
        
        route_seller = "keys/" + product["seller"] + "/" + product["seller"] + "_public_key.pem"
        #ENCRIPTO MENSAJE
        token = self.access_server.encrypt_with_symetric(content.encode("utf-8"), key)
        #ENCRIPTO LA CLAVE SIMETRICA CON LA PUBLICA DE SELLER
        encrypted_simetric_key = self.access_server.encrypt_with_public(key, route_seller)
        #COMO ES LA PRIMERA VEZ, ENCRIPTO TMB ESTO CON LA PRIVADA DE BUYER 

        route_buyer = "keys/" + buyer + "/" + buyer + "_private_key.pem"
        route_buyer_pub = "keys/" + buyer + "/" + buyer + "_public_key.pem"
        #FIRMO LA CLAVE SIMETRICA ENCRIPTADA
        sign = self.access_server.sign_with_private(encrypted_simetric_key, route_buyer)
        #ENCRIPTO LA CLAVE SIMETRICA CON LA PUBLICA DE BUYER
        encrypted_simetric_key2 = self.access_server.encrypt_with_public(key, route_buyer_pub)
        
        #GUARDO
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
            route = "keys/" + username + "/" + username + "_private_key.pem"

            #private_key = self.access_server.return_private_key(username)
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
                    #COJO LA PUBLICA DEL SENDER SIN FIRMAR
                    sim_key_decrypted = self.access_server.decrypt_with_private(sim_key_encrypted, route)
                
                else:
                    #COJO LA PUBLICA DEL SENDER
                    route_sender_pub = "keys/" + message["Sender"] + "/" + message["Sender"] + "_public_key.pem"
                    self.access_server.verify_with_public(sign, sim_key_encrypted, route_sender_pub)
                    sim_key_decrypted = self.access_server.decrypt_with_private(sim_key_encrypted, route)
                token = self.access_server.decrypt_with_symetric(encrypted_message.encode("utf-8"), sim_key_decrypted)
                print("\n" + message["Sender"] + ": " + token.decode())
                if input("\nDo you want to reply? Type Y/N: ") == "Y":
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

        route_usr_pub = "keys/" + username + "/" + username + "_public_key.pem"
        message = message.encode("utf-8")
        encrypted_message = self.access_server.encrypt_with_public(message, route_usr_pub)
        to_save = {"Owner": username, "Sender": sender, "message": encrypted_message}
        read_data.append(to_save)
        print("\nMessage moved to read.\n")
        self.access_server.save_jsons(read_data,'jsones/m_read.json')
        
    def read_messages(self, username):
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
            decrypted_message = self.access_server.decrypt_with_private(message["message"], "keys/" + username + "/" + username + "_private_key.pem")
            print("\nMensaje de:", message["Sender"], " :", decrypted_message.decode('utf-8'))

        

    
    def respond_message(self, message, sender):
        list_messages = self.access_server.open_and_return_jsons('jsones/m_unread.json')
        content ="\n" + sender + ' has replied: '
        content += input("Write your message: ")
        keys = self.access_server.open_and_return_jsons('jsones/simetric_keys.json')
        key = 0

        #Coger la clave privada del usuario para desencriptar
        route = "keys/" + sender + "/" + sender + "_private_key.pem"
        for participant in keys:
            if participant["Receiver"] == message["Receiver"] and participant["Sender"] == message["Sender"]:
                key = participant["Key"]
        symetric_key = self.access_server.decrypt_with_private(key, route)
        token = self.access_server.encrypt_with_symetric(content.encode("utf-8"), symetric_key)
        message = {"Sender": sender, "Receiver": message["Sender"], "message": token.decode()}
        list_messages.append(message)
        self.access_server.save_jsons(list_messages,'jsones/m_unread.json')