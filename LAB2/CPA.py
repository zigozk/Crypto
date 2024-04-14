import sys
import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt_image(input_image_path, output_image_path, key , iv):

    input_image = cv2.imread(input_image_path)
    input_row , input_column , input_depth = input_image.shape    

    input_image_bytes = input_image.tobytes()
    

    cipher = AES.new(key , AES.MODE_CBC , iv)

    image_bytes_padded = pad(input_image_bytes , 16) #填充
    cihpertext = cipher.encrypt(image_bytes_padded) #加密

    padsize = len(image_bytes_padded) - len(input_image_bytes)

    _pad = input_column * input_depth - 16 - padsize
    ciphertext_padded = iv + cihpertext + bytes(_pad) #拼接

    finally_ciphertext = np.frombuffer(ciphertext_padded , dtype=input_image.dtype).reshape(input_row + 1 , input_column , input_depth) #转化

    cv2.imwrite(output_image_path, finally_ciphertext) #保存

def decrypt_image(input_image_path, output_image_path, key):
    encrypt_image = cv2.imread(input_image_path)
    encrypt_image_bytes = encrypt_image.tobytes()

    encry_row , encry_column , encry_depth = encrypt_image.shape

    iv = encrypt_image_bytes[:16]


    input_image_size = ((encry_row - 1) * encry_column * encry_depth)
    padsize = (input_image_size // 16 + 1) * 16 - input_image_size
    
    ciphertext = encrypt_image_bytes[16 : 16 + input_image_size + padsize]

    cipher = AES.new(key , AES.MODE_CBC , iv)
    plaintext = cipher.decrypt(ciphertext)

    plaintext_unpad = unpad(plaintext , 16)

    plaintext_image = np.frombuffer(plaintext_unpad , encrypt_image.dtype).reshape(encry_row - 1 , encry_column , encry_depth)


    cv2.imwrite(output_image_path, plaintext_image)
    

key = get_random_bytes(16)
iv = get_random_bytes(16)
print(key)
# 加密图像
encrypt_image('C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB2\\input_image.jpeg', 'C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB2\\encrypted_image.bmp', key , iv)

# 解密图像
decrypt_image('C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB2\\encrypted_image.bmp', 'C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB2\\decrypted_image.bmp', key)
#key: b'\xda\xf5\nG\xe0\xf7\tN\xfa \x10\xfe\xaa\xb4\xc6\xe1'