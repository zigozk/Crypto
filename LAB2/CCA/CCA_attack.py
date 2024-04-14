import random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import numpy as np
from PIL import Image
import os
import hmac

def modify_image(width , height , image_data, num_pixels):
    # 计算图像的总像素数
    total_pixels = height * width

    # 从图像中随机选择100个像素点的索引
    pixel_indices = random.sample(range(total_pixels), num_pixels)

    # 将选定的像素点的RGB值设置为随机的彩色
    for index in pixel_indices:
        # 计算像素点的行号和列号
        row = index // width
        col = index % width

        # 计算像素点在图像数据中的索引
        pixel_index = (row * width + col) * 3  # 每个像素由3个字节组成(RGB)

        # 生成随机的彩色值
        red = random.randint(0, 255)
        green = random.randint(0, 255)
        blue = random.randint(0, 255)

        # 将选定像素点的RGB值设置为随机的彩色
        image_data[pixel_index:pixel_index + 3] = bytes([red, green, blue])

        return image_data

def decrypt(key , input_file , output_file) :
    aesgcm = AESGCM(key)
    with open(input_file , "rb") as f :
        bmphead = bytearray(f.read(55)) #获取文件头
        nonce = bytearray(f.read(12)) #nonce
        # print(nonce.hex().upper())
        hmac_v = bytearray(f.read(32)) #hmac
        print("hmac: " , hmac_v.hex().upper())
        encrypted_image = bytearray(f.read())
    hmac_value = hmac.new(key , encrypted_image , digestmod='sha256').digest()
    print("hmac_value: " , hmac_value.hex().upper())
    if (hmac_v == hmac_value) :
        bmphead[10] = 54 #修改图像数据起始位置
        ciphertext = np.array(encrypted_image)
        decrypted_img = aesgcm.decrypt(nonce , ciphertext.tobytes(), None) #解密
        with open(output_file , "wb") as f :
            f.write(bmphead)
            f.write(decrypted_img)        
        print("验证通过, 解密成功")
    else :
        with open(output_file , "wb") as f :
            f.write(bmphead)
            f.write(nonce)
            f.write(hmac_v)
            f.write(encrypted_image)
        print("验证失败，解密失败")

# 加载加密的图像数据
with open("C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB2\\CCA\\encrypted_image.bmp", "rb") as f:
    encrypted_image_data = bytearray(f.read())

# 将加密数据拆分为文件头和图像数据
bmphead = encrypted_image_data[:98]
image_data = encrypted_image_data[98:]

# 修改图像数据
image_data = modify_image(int.from_bytes(bmphead[18:22], byteorder='little') , int.from_bytes(bmphead[22:26], byteorder='little') ,image_data, 100)

# 将修改后的数据保存为新的文件
tampered_encrypted_image_data = bmphead + image_data
tampered_file = "C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB2\\CCA\\tampered_encrypted_image.bmp"
with open(tampered_file, "wb") as f:
    f.write(tampered_encrypted_image_data)
tempered_output_file = "C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB2\\CCA\\tampered_decrypted_image.bmp"
# 使用解密预言机尝试解密篡改后的图片
key = b'4\xb2\xd4y\xa8{&\xd2\rE~\xf9\xbfV\x1c\xc9'
decrypt(key , tampered_file , tempered_output_file)
