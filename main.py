from cryptography.fernet import Fernet
from user import user


class App():
    def __init__(self):
        print('Welcome to the app, if anytime you want to exit, press Ctrl + C')
        self.run()

    def signup(self):
        username = input('Enter username: ')
        password = input('Enter password: ')
        user(username, password)


    def login(self):
        print("Logged in")


    #que la app esté siempre activa salvo que se pulse ctrl+c
    def run(self):
        while True:
            try:
                myinput = input("Hi. If you already have a registered username please type 'Log in' \n If you otherwise want to sign up, please type 'Sign up': ")
                print( myinput)
                while  myinput != "Log in" and myinput != "Sign up":
                    myinput = input("Please type 'Log in' or 'Sign up': ")
                if myinput == "Sign up":
                    self.signup()
                else:
                    self.login()
                
            except KeyboardInterrupt:
                print('Goodbye')
                break






app = App()