from cryptography.fernet import Fernet
from user import user


class App():
    def __init__(self):
        self.users = []

    def login(self):
        username = input('Enter username: ')
        password = input('Enter password: ')
        user(username, password)


app = App()