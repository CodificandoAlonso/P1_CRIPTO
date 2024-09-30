from cryptography.fernet import Fernet
from user import user
from server import Server
import getpass

class App():
    def __init__(self):
        print('Welcome to the app, if anytime you want to exit, press Ctrl + C.\n While you are logged in, if you press Ctrl + E, you will be logged out')
        self.logged = False
        self.run()

    def signup(self):
        username = input('Enter username: ')
        password = getpass.getpass('Enter password: ')
        user(username, password)


    def login(self):
        username = input('Enter username: ')
        if Server.check_username(username):
            password = getpass.getpass('Enter password: ')
            if Server.check_password(username, password):
                print('You are logged in')
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

                    myinput = input("Hi. If you already have a registered username please type 'Log in' \n If you otherwise want to sign up, please type 'Sign up': ")
                    while  myinput != "Log in" and myinput != "Sign up":
                        myinput = input("Please type 'Log in' or 'Sign up': ")
                    if myinput == "Sign up":
                        self.signup()
                        print("\n User created.\n Now you can log in. \n")
                    else:
                        if self.login():
                            self.logged = True
                else:
                    whatodo = input("You are logged in\n You can either view the available products(Type 'View products'), put products on sale('Sale'), view your messages('Messages') or log out(Type 'Log out')\n")
                    while whatodo != "View products" and whatodo != "Sale" and whatodo != "Messages" and whatodo != "Log out":
                        whatodo = input("Please type 'View products', 'Sale', 'Messages' or 'Log out': ")
                    if whatodo == "View products":
                        Server.show_products(self.username)
                    elif whatodo == "Sale":
                        Server.add_products(self.username)
                    elif whatodo == "Messages":
                        print("Messages")
                    else:
                        self.logged = False
                        print("You have logged out")
            except KeyboardInterrupt:
                print('Goodbye')
                break





app = App()