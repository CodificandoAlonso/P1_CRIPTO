import json
import re


class user():
    def __init__(self, username, password):
        self.username = validate_user(username)
        self.password = validate_password(password)
        #save_user()


def validate_user(username):
    while len(username) < 5:
        print('Username must be at least 5 characters long')
        username = input('Enter username again: ')
    
    """with open('jsones/users.json', 'r') as file:
        users = json.load(file)
        while username in users:
            print('Username already exists')
            username = input('Enter username again: ')"""

def validate_password(password):
    while len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password):
        print('Password must be at least 8 characters long and contain at least one uppercase letter, one digit and one special character')
        password = input('Enter password again: ')
    print("Your password has been saved carapito")
    #return password


#or not any (bool(re.search(r'[^a-zA-Z0-9]', password))):

#def save_user():