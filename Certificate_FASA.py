from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import os
import datetime
from cryptography.hazmat.primitives import hashes





class All_Certificates():
    def __init__(self):
        self.issuer_FASA = None
        self.subject_FASA = None
        self.certificate_FASA = None
        self.authority_dir_FASA = os.path.join(os.getcwd(),'keys' ,'Authorities', 'FASA')
        if not os.path.isdir(self.authority_dir_FASA):
            os.makedirs(self.authority_dir_FASA, exist_ok=True)
            self.create_pepe_keys_FASA()
        self.__private_key_FASA, self.__public_key_FASA = self.get_keys_FASA()

        if not os.path.isdir(self.authority_dir_FASA + "FASA_cert.pem"):
            self.generate_certificate_FASA()
        else:
            self.load_certificate_FASA()
        
        

        self.authority_dir_MVSA = os.path.join(os.getcwd(), 'keys', 'Authorities', 'MVSA')
        self.certificate_MVSA = None
        if not os.path.isdir(self.authority_dir_MVSA):
            os.makedirs(self.authority_dir_MVSA, exist_ok=True)
            self.create_pepe_keys_MVSA()
        self.__private_key_MVSA, self.__public_key_MVSA = self.get_keys_MVSA()
        if not os.path.isdir(self.authority_dir_FASA + "MVSA_cert.pem"):
            self.generate_certificate_MVSA()
        else:
            self.load_certificate_MVSA()

        self.authority_dir_CSSA = os.path.join(os.getcwd(), 'keys', 'Authorities', 'CSSA')
        self.certificate_CSSA = None
        if not os.path.isdir(self.authority_dir_CSSA):
            os.makedirs(self.authority_dir_CSSA, exist_ok=True)
            self.create_pepe_keys_CSSA()
        self.__private_key_CSSA, self.__public_key_CSSA = self.get_keys_CSSA()
        if not os.path.isdir(self.authority_dir_FASA + "CSSA_cert.pem"):
            self.generate_certificate_CSSA()
        else:
            self.load_certificate_CSSA()




    def create_pepe_keys_FASA(self):
        private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size = 4096,
            )
        public_key = private_key.public_key()
        with open(self.authority_dir_FASA + "/FASA_private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(self.authority_dir_FASA + "/FASA_public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))



    def get_keys_FASA(self):
        with open(self.authority_dir_FASA + "/FASA_private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
        with open(self.authority_dir_FASA + "/FASA_public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key
    

    def generate_certificate_FASA(self):
        self.subject_FASA = self.issuer_FASA = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"ASTURIAS"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"OVIEDO"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Fernando Alonso Shopping Authority"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u"FASA"),
        ])
        
        self.certificate_FASA = x509.CertificateBuilder().subject_name(
                self.subject_FASA
            ).issuer_name(
                self.issuer_FASA
            ).public_key(
                self.__public_key_FASA
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
                x509.SubjectKeyIdentifier.from_public_key(self.__public_key_FASA),
                critical=False,
            ).sign(self.__private_key_FASA, hashes.SHA256())


        with open(self.authority_dir_FASA + "/FASA_cert.pem", "wb") as f:
            f.write(self.certificate_FASA.public_bytes(serialization.Encoding.PEM))


    def create_pepe_keys_MVSA(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        public_key = private_key.public_key()
        with open(self.authority_dir_MVSA + "/MVSA_private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(self.authority_dir_MVSA + "/MVSA_public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))


    def get_keys_MVSA(self):
        with open(self.authority_dir_MVSA + "/MVSA_private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
        with open(self.authority_dir_MVSA + "/MVSA_public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key


    def generate_certificate_MVSA(self):
        self.subject_MVSA = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"NL"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"AMSTERDAM"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"ZANDVOORT"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Max Verstappen Shopping Authority"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u"MVSA"),
        ])
        self.certificate_MVSA = x509.CertificateBuilder().subject_name(
            self.subject_MVSA
        ).issuer_name(
            self.certificate_FASA.subject
        ).public_key(
            self.__public_key_MVSA
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            # Our intermediate will be valid for ~3 years
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * 3)
        ).add_extension(
            # Allow no further intermediates (path length 0)
            x509.BasicConstraints(ca=True, path_length=0),
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
            x509.SubjectKeyIdentifier.from_public_key(self.__public_key_MVSA),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                self.certificate_FASA.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        ).sign(self.__private_key_FASA, hashes.SHA256())

        with open(self.authority_dir_MVSA + "/MVSA_cert.pem", "wb") as f:
            f.write(self.certificate_MVSA.public_bytes(serialization.Encoding.PEM))




    def create_pepe_keys_CSSA(self):
        private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size = 4096,
            )
        public_key = private_key.public_key()
        with open(self.authority_dir_CSSA + "/CSSA_private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(self.authority_dir_CSSA + "/CSSA_public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

    def get_keys_CSSA(self):
        with open(self.authority_dir_CSSA + "/CSSA_private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
        with open(self.authority_dir_CSSA + "/CSSA_public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key




    def generate_certificate_CSSA(self):
        self.subject_CSSA = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"MADRID"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"POZUELO DE ALARCON"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Carlos Sainz Shopping Authority"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u"CSSA"),
        ])
        self.certificate_CSSA = x509.CertificateBuilder().subject_name(
            self.subject_CSSA
        ).issuer_name(
            self.subject_FASA
        ).public_key(
            self.__public_key_CSSA
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            # Our intermediate will be valid for ~3 years
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * 3)
        ).add_extension(
            # Allow no further intermediates (path length 0)
            x509.BasicConstraints(ca=True, path_length=0),
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
            x509.SubjectKeyIdentifier.from_public_key(self.__public_key_CSSA),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                self.certificate_FASA.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        ).sign(self.__private_key_FASA, hashes.SHA256())

        with open(self.authority_dir_CSSA + "/CSSA_cert.pem", "wb") as f:
            f.write(self.certificate_CSSA.public_bytes(serialization.Encoding.PEM))


    def create_certificate_CSSA(self, username, country):
        subject = x509.Name([
     x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "ES"),
    x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, country),
     x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "MADRID"),
     x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, username),
])
        with open("keys/" + username + "/"+username+"_public_key.pem", "rb") as f:
            user_public = serialization.load_pem_public_key(
                f.read()
            )
        ee_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.subject_CSSA
        ).public_key(
            user_public
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            # Our cert will be valid for 10 days
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([
                # Describe what sites we want this certificate for.
                x509.DNSName("cryptography.io"),
                x509.DNSName("www.cryptography.io"),
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(user_public),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                self.certificate_CSSA.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        ).sign(self.__private_key_CSSA, hashes.SHA256())

        with open("keys/" + username + "/"+username+"_cert.pem", "wb") as f:
            f.write(ee_cert.public_bytes(serialization.Encoding.PEM))




    def create_certificate_MVSA(self, username, country):
        subject = x509.Name([
     x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "NL"),
    x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, country),
     x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "NETHERLANDS"),
     x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, username),
])
        with open("keys/" + username + "/"+username+"_public_key.pem", "rb") as f:
            user_public = serialization.load_pem_public_key(
                f.read()
            )
        ee_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.subject_MVSA
        ).public_key(
            user_public
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            # Our cert will be valid for 10 days
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([
                # Describe what sites we want this certificate for.
                x509.DNSName("cryptography.io"),
                x509.DNSName("www.cryptography.io"),
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(user_public),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                self.certificate_MVSA.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        ).sign(self.__private_key_CSSA, hashes.SHA256())

        with open("keys/" + username + "/"+username+"_cert.pem", "wb") as f:
            f.write(ee_cert.public_bytes(serialization.Encoding.PEM))

    def load_certificate_FASA(self):
        with open(self.authority_dir_FASA + "/FASA_cert.pem", "rb") as f:
            self.certificate_FASA = x509.load_pem_x509_certificate(f.read())

    def load_certificate_CSSA(self):
        with open(self.authority_dir_CSSA + "/CSSA_cert.pem", "rb") as f:
            self.certificate_CSSA = x509.load_pem_x509_certificate(f.read())

    def load_certificate_MVSA(self):
        with open(self.authority_dir_MVSA + "/MVSA_cert.pem", "rb") as f:
            self.certificate_MVSA = x509.load_pem_x509_certificate(f.read())