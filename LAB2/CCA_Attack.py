import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
import random

def decrypt_image(input_image_path, output_image_path, key):
    encrypt_image = cv2.imread(input_image_path)

    encrypted_image = cv2.imread(input_image_path)
    if encrypted_image is None:
        print("Error: Unable to read the input_image")
    else:
        print("Image loaded successfully")
    
    encrypt_image_bytes = encrypt_image.tobytes()

    encry_row, encry_column, encry_depth = encrypt_image.shape

    iv = encrypt_image_bytes[:16]

    input_image_size = ((encry_row - 1) * encry_column * encry_depth)
    padsize = (input_image_size // 16 + 1) * 16 - input_image_size
    
    ciphertext = encrypt_image_bytes[16 : 16 + input_image_size + padsize]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    plaintext_unpad = unpad(plaintext, 16)

    plaintext_image = np.frombuffer(plaintext_unpad, encrypt_image.dtype).reshape(encry_row - 1, encry_column, encry_depth)

    cv2.imwrite(output_image_path, plaintext_image)

def perform_CCA_attack(input_image_path, output_image_path, key):
    # 加载密文图片
    encrypted_image = cv2.imread(input_image_path)

    # 确定篡改范围，排除初始向量部分
    height, width, _ = encrypted_image.shape
    tamper_range = [(i, j) for i in range(height) for j in range(width) if not (i == 0 and j < 16)]

    # 随机选择多个像素点进行篡改
    num_pixels_to_tamper = min(len(tamper_range), 100)  # 选择最多100个像素点进行篡改
    pixels_to_tamper = random.sample(tamper_range, num_pixels_to_tamper)
    for pixel in pixels_to_tamper:
        encrypted_image[pixel[0], pixel[1], random.randint(0, 2)] = random.randint(0, 255)

    print("Tampering successful")

    # 保存篡改后的图片
    cv2.imwrite(output_image_path, encrypted_image)

    # 使用解密函数对篡改图片进行解密
    decrypt_image(output_image_path, 'C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB2\\decrypted_image_after_attack.bmp', key)

key = b'q\xe0gY\x98\xc0\xc6\xbf\x18\xfa\x1au/\xbb|\xe8'

# 进行 CCA 攻击并尝试解密
perform_CCA_attack('C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB2\\encrypted_image.bmp', 'C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB2\\tampered_encrypted_image.bmp', key)
