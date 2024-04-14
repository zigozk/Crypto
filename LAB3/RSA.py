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

def encrypt(key) :
    with open("C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB2\\CCA\\input_image.bmp" , 'rb') as f:
        input_image = bytearray(f.read())

    input_image[10] = 98 #修改图片数据起始位置

    plaintext = np.array(input_image[55: ]) #记录图片数据
    #加密过程
    aesgcm = AESGCM(key)
    # print("key: " ,  key)
    nonce = os.urandom(12)
    # print("nonce: " , nonce.hex().upper())
    ciphertext = aesgcm.encrypt(nonce , plaintext.tobytes() , None)
    hmac_value = hmac.new(key, ciphertext, digestmod='sha256').digest()
    # print("hmac_value: " , hmac_value.hex().upper())

    with open("C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB3\\encrypted_image.bmp" , "wb") as f :
        f.write(input_image[:55]) #文件头
        f.write(nonce) #nonce
        f.write(hmac_value) #HMAC消息
        f.write(ciphertext) #加密图像数据

def decrypt(encrypted_key) :
    key = private_key.decrypt(
        encrypted_key,
        padding=padding.PKCS1v15()
    )
    print("decrypted_key: " , key)
    aesgcm = AESGCM(key)
    with open("C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB3\\encrypted_image.bmp" , "rb") as f :
        bmphead = bytearray(f.read(55)) #获取文件头
        nonce = bytearray(f.read(12)) #nonce
        # print(nonce.hex().upper())
        hmac_v = bytearray(f.read(32)) #hmac
        # print(hmac_v.hex().upper())
        encrypted_image = bytearray(f.read())
    hmac_value = hmac.new(key , encrypted_image , digestmod='sha256').digest()
    if (hmac_v == hmac_value) :
        bmphead[10] = 54 #修改图像数据起始位置
        ciphertext = np.array(encrypted_image)
        decrypted_img = aesgcm.decrypt(nonce , ciphertext.tobytes(), None) #解密
        with open("C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB3\\decrypted_image.bmp" , "wb") as f :
            f.write(bmphead)
            f.write(decrypted_img)        
        print("验证通过, 解密成功")
    else :
        with open("C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB3\\decrypted_image.bmp" , "wb") as f :
            f.write(bmphead)
            f.write(nonce)
            f.write(hmac_v)
            f.write(encrypted_image)
        print("验证失败，解密失败")


key = AESGCM.generate_key(bit_length=128)

#加载公钥
with open("C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB3\\rsa_public_key.pem", "rb") as pem_file_public:
    public_key = serialization.load_pem_public_key(
        pem_file_public.read(),
        backend=default_backend()
    )

# 加载私钥
with open("C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB3\\rsa_private_key.pem", "rb") as pem_file_private:
    private_key = serialization.load_pem_private_key(
        pem_file_private.read(),
        password=None,  # 如果私钥使用了密码，这里需要提供密码
        backend=default_backend()
    )

#加密AES密钥
encrypted_key = public_key.encrypt(
    key,
    padding=padding.PKCS1v15()
)
print("key: " , key)
print("encrypted_key: " , encrypted_key)
encrypt(key)
decrypt(encrypted_key)
