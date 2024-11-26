from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import os

class CSSA_Subroot():
    def __init__(self):
        self.authority_dir = os.path.join(os.getcwd(),'keys' ,'Authorities', 'CSSA')
        if not os.path.isdir(self.authority_dir):
            os.makedirs(self.authority_dir, exist_ok=True)
            self.create_pepe_keys()
        self.__private_key, self.__public_key = self.get_keys()




    def create_pepe_keys(self):
        private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size = 4096,
            )
        public_key = private_key.public_key()
        with open(self.authority_dir + "/CSSA_private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(self.authority_dir + "/CSSA_public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

    def get_keys(self):
        with open(self.authority_dir + "/CSSA_private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
        with open(self.authority_dir + "/CSSA_public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key
    

CSSA_Subroot()