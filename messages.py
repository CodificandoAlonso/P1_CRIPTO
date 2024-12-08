from cryptography.fernet import Fernet
import os
from cryptography.hazmat.primitives import hashes,hmac


class Message():
    
    def __init__(self, server):
        self.access_server = server

    def send_messages(self, product, buyer):
        list_messages = self.access_server.open_and_return_jsons('jsones/m_unread.json')
        buyer_chain = self.access_server.return_chain(buyer)
        content = "Product: " + product["name"] + " : "
        content += input("Write your message: ")


        keys = self.access_server.open_and_return_jsons('jsones/simetric_keys.json')
        key = 0
        for participant in keys:
            if participant["Receiver"] == buyer and participant["Sender"] == product["seller"]:
                key = participant["Key"]

        if key == 0: #NO COMUNICACION
            key = Fernet.generate_key()
        else:
            route = "keys/" + buyer + "/" + buyer + "_private_key.pem"
            simetric_hash = self.access_server.decrypt_with_private(key[0:512],route)
            sign_1 = self.access_server.decrypt_with_private(key[512:1024],route)
            sign_2 = self.access_server.decrypt_with_private(key[1024:],route)
            
            sim_key_decrypted = simetric_hash[0:-16]
            token = simetric_hash[-16:]
            
            key_hash = token
            h = hmac.HMAC(key_hash, hashes.SHA256())
            h.update(sim_key_decrypted)
            h = h.finalize()
            self.access_server.verify_with_public(sign_1 + sign_2, h, "keys/" + product["seller"] + "/" + product["seller"] + "_public_key.pem")
            token = self.access_server.encrypt_with_symetric(content.encode("utf-8"), sim_key_decrypted)
            list_messages.append({"Sender": buyer, "Receiver": product["seller"], "message": token.decode()})
            return self.access_server.save_jsons(list_messages,'jsones/m_unread.json')
            
        seller_chain = self.access_server.return_chain(product["seller"])
        if self.access_server.check_chain(seller_chain) == False:
            raise Exception("Chain not valid")

        route_seller = "keys/" + product["seller"] + "/" + product["seller"] + "_public_key.pem"

        #ENCRIPTO MENSAJE

        token = self.access_server.encrypt_with_symetric(content.encode("utf-8"), key)

        #ENCRIPTO LA CLAVE SIMETRICA CON LA PUBLICA DE SELLER
        route = "keys/" + buyer + "/" + buyer + "_private_key.pem"
        key_hash = os.urandom(16)
        h = hmac.HMAC(key_hash, hashes.SHA256())
        h.update(key)
        h = h.finalize()
        signed_hash = self.access_server.sign_with_private(h, route)
        
        signed_hash_1 = signed_hash[0:255]
        signed_hash_2 = signed_hash[255:]




        encrypted_simetric_key_1 = self.access_server.encrypt_with_public(key + key_hash, route_seller)
        encrypted_simetric_key_2 = self.access_server.encrypt_with_public(signed_hash_1, route_seller)
        encrypted_simetric_key_3 = self.access_server.encrypt_with_public(signed_hash_2, route_seller)

        #BUSCAMOS LA CLAVE PUBLICA DE BUYER
        route_buyer_pub = "keys/" + buyer + "/" + buyer + "_public_key.pem"

        #ENCRIPTO LA CLAVE SIMETRICA CON LA PUBLICA DE BUYER

        
        #GUARDO
        content_to_save = {"Sender": buyer, "Receiver":product["seller"], "Key": encrypted_simetric_key_1 + encrypted_simetric_key_2 + encrypted_simetric_key_3, "Chain": buyer_chain}
        keys.append(content_to_save)
        content_to_save = {"Sender": product["seller"], "Receiver":buyer, "Key": "WAITING FOR RESPONSE", "Chain": "YOU NEED TO DELETE THIS"}
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
                for item in conversations:
                    if item["Receiver"] == username and message["Sender"] == item["Sender"]:
                        sim_key_encrypted = item["Key"]
                        chain = item["Chain"]
                        if chain != "Verified":
                            if self.access_server.check_chain(chain) == False:
                                raise Exception("Chain not valid")
                        
                            route = "keys/" + username + "/" + username + "_private_key.pem"
                            simetric_hash = self.access_server.decrypt_with_private(sim_key_encrypted[0:512],route)
                            sign_1 = self.access_server.decrypt_with_private(sim_key_encrypted[512:1024],route)
                            sign_2 = self.access_server.decrypt_with_private(sim_key_encrypted[1024:],route)
                            
                            sim_key_decrypted = simetric_hash[0:-16]
                            token = simetric_hash[-16:]
                            
                            key_hash = token
                            h = hmac.HMAC(key_hash, hashes.SHA256())
                            h.update(sim_key_decrypted)
                            h = h.finalize()
                            self.access_server.verify_with_public(sign_1 + sign_2, h, "keys/" + message["Sender"] + "/" + message["Sender"] + "_public_key.pem")
                            conversations.remove(item)
                            conversations.append({"Sender": message["Sender"], "Receiver": username, "Key": sim_key_encrypted, "Chain": "Verified"})

                for participant in conversations:
                    if participant["Receiver"] == message["Sender"] and participant["Sender"] == message["Receiver"] and participant["Key"] == "WAITING FOR RESPONSE":
                            route = "keys/" + username + "/" + username + "_private_key.pem"
                            key_hash = os.urandom(16)
                            h = hmac.HMAC(key_hash, hashes.SHA256())
                            h.update(sim_key_decrypted)
                            h = h.finalize()
                            signed_hash = self.access_server.sign_with_private(h, route)
                            
                            signed_hash_1 = signed_hash[0:255]
                            signed_hash_2 = signed_hash[255:]
                            route = "keys/" + message["Sender"] + "/" + message["Sender"] + "_public_key.pem"
                            encrypted_simetric_key_1 = self.access_server.encrypt_with_public(sim_key_decrypted + key_hash, route)
                            encrypted_simetric_key_2 = self.access_server.encrypt_with_public(signed_hash_1, route)
                            encrypted_simetric_key_3 = self.access_server.encrypt_with_public(signed_hash_2, route)
                            conversations.remove(participant)
                            conversations.append({"Sender": message["Receiver"], "Receiver": message["Sender"], "Key": encrypted_simetric_key_1 + encrypted_simetric_key_2 + encrypted_simetric_key_3, "Chain": "Verified"})
                            self.access_server.save_jsons(conversations, "jsones/simetric_keys.json")

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
                sim_key_encrypted = participant["Key"]
        simetric_hash = self.access_server.decrypt_with_private(sim_key_encrypted[0:512],route)
        sign_1 = self.access_server.decrypt_with_private(sim_key_encrypted[512:1024],route)
        sign_2 = self.access_server.decrypt_with_private(sim_key_encrypted[1024:],route)
        
        sim_key_decrypted = simetric_hash[0:-16]
        token = simetric_hash[-16:]
        
        key_hash = token
        h = hmac.HMAC(key_hash, hashes.SHA256())
        h.update(sim_key_decrypted)
        h = h.finalize()
        self.access_server.verify_with_public(sign_1 + sign_2, h, "keys/" + message["Sender"] + "/" + message["Sender"] + "_public_key.pem")
        token = self.access_server.encrypt_with_symetric(content.encode("utf-8"), sim_key_decrypted)
        message = {"Sender": sender, "Receiver": message["Sender"], "message": token.decode()}
        list_messages.append(message)
        self.access_server.save_jsons(list_messages,'jsones/m_unread.json')