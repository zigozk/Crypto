import secrets

def generate_key(plaintext) :
    key = secrets.token_hex(len(plaintext))
    return key

def encrypt(plaintext , key) :
    ciphertext = ""
    for i in range(int(len(plaintext)/2)) :
        int1 = int(plaintext[i * 2 : i * 2 + 2] , 16)
        int2 = int(key[i * 2 : i * 2 + 2] , 16)
        ciphertext += format(int1 ^ int2 , '02x')
    return ciphertext

def decrypt(ciphertext , key) :
    plaintext = ""
    for i in range(int(len(ciphertext)/2)) :
        int1 = int(ciphertext[i * 2 : i * 2 + 2] , 16)
        int2 = int(key[i * 2 : i * 2 + 2] , 16)
        plaintext += chr(int1 ^ int2)   
    return plaintext
    


plaintext = "Hello World!"
key = generate_key(plaintext.encode().hex())
print("key: " , key)
ciphertext = encrypt(plaintext.encode().hex() , key)
print("ciphertext: " , ciphertext)
print("plaintext: " , decrypt(ciphertext , key))
