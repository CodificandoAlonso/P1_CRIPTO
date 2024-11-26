from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import os
import datetime
from cryptography.hazmat.primitives import hashes


#SU UNICA FUNCION ES VERIFICAR CERTIFICADOS. SE AUTENTICA A SI MISMA CON SU PROPIO CERTIFICADO
class FASA_Root():
    def __init__(self):
        self.authority_dir = os.path.join(os.getcwd(),'keys' ,'Authorities', 'FASA')
        if not os.path.isdir(self.authority_dir):
            os.makedirs(self.authority_dir, exist_ok=True)
            self.create_pepe_keys()
        self.__private_key, self.__public_key = self.get_keys()
        self.generate_cert()




    def create_pepe_keys(self):
        private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size = 4096,
            )
        public_key = private_key.public_key()
        with open(self.authority_dir + "/FASA_private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(self.authority_dir + "/FASA_public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))



    def get_keys(self):
        with open(self.authority_dir + "/FASA_private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
        with open(self.authority_dir + "/FASA_public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key
    

    def generate_cert(self):
        subject = issuer = self.certificate.issuer_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"ASTURIAS"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"OVIEDO"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Fernando Alonso Shopping Authority"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u"FASA"),
        ]))
        
        self.certificate = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                self.__public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
            ).not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365*10)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.__public_key),
                critical=False,
            ).sign(self.__private_key, hashes.SHA256())

        with open(self.authority_dir + "/FASA_cert.pem", "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        return certificate




FASA_Root()