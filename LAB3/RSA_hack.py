from Crypto.Cipher import AES
from PIL import Image
import numpy as np
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse
from base64 import b64decode
from math import gcd
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
from Crypto.Cipher import PKCS1_OAEP
public_key1_text = """
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuz20BUTcqVDjzEOKiJF9
66LbQB/59lnXTj/SmiD07mV1XE03BLrWfi7jFh/iq5ZPzVXfbNPjHiojO9WRhWzr
wiQGZNVZ7qFoO/PzXOT8OyHyOMcrb6ogtCyFvDOeximr3M/ICmliU2JxbLSfteZj
AplHJVgs5bJ5LTW7eSy1x2Z5aOsHjesK3rkLi1yB2jM0MeaNIB/Enb82bBMKzAam
vN6tY8bQbEoRbTnlX6PUfkU9w7XsWLMa3QbpIH9mNam1Qz4ynCjWXcDo6KzYotUf
TgGlIIOOJKsAqgOgSHqTz83e8bBizPwJg+CxBzP4Ha8C9phc41i2GiEgDf4J1J0R
0BZDcJEgZIlI+B5tlvJTy/uQyvmEP+hyMD8d83RdzLYy9h8u0MNHjJygY/Kktftp
wPtZPThpMOWWbOMM72a8Y2usz5rKTBAe+bN5QyELCErc/aQB0ABUSsNf4XxaQWbz
gJdb3hEvUkas0PfHui8UB6Yuaa7RmEE6EPIELx2WF2BGw1AG8vg5mi3I+HYxpk9W
mxy2gj63UPqr1f0u7+fnig7ANlyyPYG3LLUfhBT/d9VH0W644lqF8eZo0INEHfQf
+g4qvVVSTWfuC84ky5gTnWMbzB0iqVsZD3xw4wfSrSKyK6QFNESNdOo+1E0nz83I
cQAFD+zSSMLgodHCgA9GlGECAwEAAQ==
-----END PUBLIC KEY-----
"""
public_key2_text = """
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAymf92H5ljvvfTE8QjuOd
xv7YPOxXC05VceuSjtZN1aDb/4gqpWxDyMzRrPS8VRQTxkqWia4nd//zj+dheHNv
6+Emb3f00IyC2bcAFvDgQmnQB0sJZf2UI3mbMfLdnsIYW2YCbvxEiFYmUUOnh6xP
AnYFtZuvh9EDpyUwT95thQS23UEO2M1y5Q9SRUZo4EeQGb6/iqB6Q5FYabRqbsXe
Ckqxk1ENkPpuLkiQCtra++bICj4WbfVCOiiYpaN/faVud6qMHxsCxxkk+2p7kcs3
ZsCSEmLBzFNmzT32pMK9pq/rAXyXbGh4ECDuTdk1va/cCxIr5Ongven4oe4qGdnj
OCD9xPNfQZDSpYMaBcn1UveM9Rrv/GYaC9AgMnVvG5PaQOYKJzETU2gJm4rdPp/M
Hc9CvN30B6X9ewsLYIaA8ES/DRIqMG4GKAgMz0siROwLXMSkLXg1u4+mLeQzBQP5
TPJ5qwAwKJc6uPPoXo9ZmFnFW4THCoEJ+caax9M0Urg4+B6ids73C2u8A6xqVXld
ng0pAdt5exZqckhPWaWajFt4mmbUmlot7GU9PxV+NDhCn4YDmhBKQRin4lkuLilM
0/WmvnVxD7IhgXbDYrP7E1j/IO9VZQOGkntVT/BtvhJLQauF6J2bxyct9GD6Ahg4
BBKL1/FPLaDsmzWqbNiJKp8CAwEAAQ==
-----END PUBLIC KEY-----
"""

encrypted_key_Base64 = """
MzhKNQx+U8ltsj5is29pSwu7yqdgoWPWIhgEwUTz3ywE84ue99Z7T/AISGOuyud6ET4E8xXFS/7wadzwYj3yL6dQrw+F9KFPJRNkTDQll0Re+3kkGt2+M68HJRvmIcJaD1/0PNTv9gek5PdL59TNq/VerwqXusAIIOdclwhb+U1EGJzJ0RS+8Wyp/+PU4J5P2mtFSak5SKNzDB8yg00uyhRBZGriQzw+QQRZanWJYs45UFYIP+9ZMUK3lOkf3b8CT+qGW/HcDFwG59hn59PUvN8UFER3PcOTIRD/+RBSKoi1Sdr7uxvQ3XTBvFJKlDMp1es4yzewmOgluBY2DtGV+aAbLzu5Sy6EfF7tJgid8V9T9ZQ8nqW9vtWkt6Y2okRhdkpX+E+y240gU1BEHOUNglM6oJ1b0nGiAL5cjUtX0IknEAsZR/U2ztsMQRzvy10xJpIgipKB52aNh6BnYzFH4DYndfehKh1NjVckcJOK+krTiUNwQMNhRYSZ8v1pZH6jR96TuDPib1KcJopjaGdf9zNa2bkdJ7NSWTe9j1jHMPJYjrP6XCefsixRTWp5dEz3KgzWEgGBHmIhz2SYYWLcy0SKb3ljYFUrY6tDwVRC+Srkk4GOeS09OvxT3r9E/JdaiA9BXuRjrV7LeCAW18AwbpZEaTHxjrVcoZ5sWpNasCI=
"""

# 加载公钥
public_key1 = serialization.load_pem_public_key(public_key1_text.encode(), backend=default_backend())
public_key2 = serialization.load_pem_public_key(public_key2_text.encode(), backend=default_backend())

# 获取n和e值
n1 = public_key1.public_numbers().n
n2 = public_key2.public_numbers().n
e = public_key1.public_numbers().e
print("n1: " , n1 ,"\nn2: ", n2 , "\ne: " , e)

# 获取gcd
_gcd = gcd(n1 , n2)
print("gcd: " , _gcd)

p = gcd(n1, _gcd)  # p是n和公因子的最大公约数
q = n1 // p
print("p: " , p)
print("q: " , q)
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
#拼接私钥
private_key = RSA.construct((n1 , e , d , p , q))

encrypted_symmetric_key = base64.b64decode(encrypted_key_Base64)
cipher_rsa = PKCS1_OAEP.new(private_key)
symmetric_key_base64 = cipher_rsa.decrypt(encrypted_symmetric_key)
symmetric_key = base64.b64decode(symmetric_key_base64)
print("解密后的对称密钥:", symmetric_key)

# 加载密文图像
image = Image.open("C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB3\\enc1.png\\enc1.png")
image_data = np.array(image)

image_bytes = image_data.tobytes()

# 从密文图像中提取 IV

iv = image_bytes[:16]
print("iv" , iv.hex())

padding_length = image_bytes[-4:]
padding_length = int(padding_length.hex() , 16)
print("padding_length" , padding_length)

encrypted_data = image_bytes[16 : ]
encrypted_data = encrypted_data[ : -4 * padding_length  ]

# # 创建 AES 解密器
cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)

# # 解密密文图像数据
decrypted_data_pad = cipher.decrypt(encrypted_data)
decrypted_data_unpad = unpad(decrypted_data_pad , AES.block_size)

dec_image = Image.frombytes("RGBA" ,(1920 , 1080), decrypted_data_unpad)

dec_image.save("C:\\Users\\zigo\\Desktop\\crypto\\LAB\\LAB3\\enc1.png\\dec1.png")