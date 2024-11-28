from cryptography.fernet import Fernet
from user import User
from server import Server
from messages import Message
import getpass
import os, shutil

class App():
    def __init__(self):
        print('Welcome to the app, if anytime you want to exit, press Ctrl + C.\n [DEBUG] THIS DATABASES AND THE DATA ARE BEING PROTECTED WITH ChaCha20Poly1305\n')
        self.logged = False
        self.server = Server()
        self.message = Message(self.server)
        self.run()

    def signup(self):
        username = input('Enter username: ')
        country = input('Enter country(Spain or Netherlands): ')
        password = getpass.getpass('Enter password: ')
        User(username, country, password, self.server)


    def login(self):
        username = input('Enter username: ')
        if self.server.check_username(username):
            password = getpass.getpass('Enter password: ')
            if self.server.check_password(username, password):
                self.username = username
                return True
            else:
                print('Wrong password')
                return False




    #que la app esté siempre activa salvo que se pulse ctrl+c
    def run(self):
        while True:
            try:
                if not self.logged:

                    self.manage_user_session()
                else:
                    self.handle_user_actions()
            except KeyboardInterrupt:
                self.server.delete_symetric()
                print('\nGoodbye')
                break
    
    def handle_user_actions(self):
        whatodo = input("You can either view the available products(Type 'View products'), put products on sale('Sale'), view your messages('Messages') or log out(Type 'Log out')\n")
        while whatodo != "View products" and whatodo != "Sale" and whatodo != "Messages" and whatodo != "Log out":
            whatodo = input("Please type 'View products', 'Sale', 'Messages' or 'Log out': ")
        if whatodo == "View products":
            self.server.show_products(self.username)               
        elif whatodo == "Sale":
            self.server.add_products(self.username)
        elif whatodo == "Messages":
            self.message.check_messages(self.username)
        else:
            self.logged = False
            print("You have logged out")

    def manage_user_session(self):
        myinput = input("Hi. If you already have a registered username please type 'Log in' \n If you otherwise want to sign up, please type 'Sign up': ")
        while  myinput != "Log in" and myinput != "Sign up":
            myinput = input("Please type 'Log in' or 'Sign up': ")
        if myinput == "Sign up":
            self.signup()
            print("\n User created.\n Now you can log in. \n")
        else:
            if self.login():
                self.logged = True
                print('You are logged in')


app = App()
