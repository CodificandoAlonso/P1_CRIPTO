import json
import re


class user():
    def __init__(self, username, password):
        self.username = validate_user(username)
        self.password = validate_password(password)
        save_user(self.username, self.password)


def validate_user(username):
    while len(username) < 5:
        print('Username must be at least 5 characters long')
        username = input('Enter username again: ')
    
    with open('jsones/users.json', 'r') as file:
        if not file.read().strip() == "":
                with open("jsones/users.json", "r", encoding="utf-8") as file:
                    users = json.load(file)
                while any(d['username'] == username for d in users):
                    print('Username already exists')
                    username = input('Enter username again: ')
        return username

def has_special_char(password):
    elem = r'[^\w\s]'
    return bool(re.search(elem, password))

def validate_password( password):
    while len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password) or not has_special_char(password):
        print('Password must be at least 8 characters long and contain at least one uppercase letter, one digit and one special character')
        password = input('Enter password again: ')
    print("Your password has been saved carapito")
    return password



def save_user(username, password):
    try:
        with open('jsones/users.json', 'r', encoding='utf-8') as file:
            try:
                users = json.load(file)
            except json.JSONDecodeError:
                users = []
    except FileNotFoundError:
        users = []

    users.append({'username': username, 'password': password})

    with open('jsones/users.json', 'w', encoding='utf-8') as file:
        json.dump(users, file, indent=4)
    print('User has been saved')