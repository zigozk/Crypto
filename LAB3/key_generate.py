from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import numpy as np
from PIL import Image
import os
import hmac

# 生成RSA密钥对
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# 获取公钥
public_key = private_key.public_key()

# 将私钥保存为.pem文件
pem_data_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

with open("C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB3\\rsa_private_key.pem", "wb") as pem_file_private:
    pem_file_private.write(pem_data_private)

print("Private key saved as rsa_private_key.pem")

# 将公钥保存为.pem文件
pem_data_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB3\\rsa_public_key.pem", "wb") as pem_file_public:
    pem_file_public.write(pem_data_public)

print("Public key saved as rsa_public_key.pem")