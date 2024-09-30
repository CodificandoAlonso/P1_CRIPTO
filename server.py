import json


class Server():




    def check_username(username):
        with open('jsones/users.json') as users:
            data = json.load(users)
            for user in data:
                if user['username'] == username :
                    return True
            return False
    def check_password(username, password):
        with open('jsones/users.json') as users:
            data = json.load(users)
            for user in data:
                if user["username"] == username and user["password"] == password:
                    return True
            return False
        


    def show_products(username):
        with open('jsones/products.json') as products:
            data = json.load(products)
            output = {}
            counter = 0
            for product in data:
                if product["seller"] != username:
                    output[counter] = product
                    counter += 1
            
        return print(output)
    
    def add_products(username):
        with open('jsones/products.json') as products:
            try:
                data = json.load(products)
            except json.JSONDecodeError:
                data = []
            name = input("Enter the name of the product: ")
            price = input("Enter the price of the product: ")
            data.append({"name": name, "price": price, "seller": username})
            with open('jsones/products.json', 'w', encoding='utf-8') as file:
                json.dump(data, file, indent=4)
            return print("Product added")