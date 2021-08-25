import json
import re
from base64 import b64encode, b64decode
import random
from Crypto.Cipher import AES, DES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

data = 'ejemplo sencillo para comprobar el primer metodo de encripcion CBC'
datab = bytes(data, encoding='utf-8')

#MODO CBC
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(datab, AES.block_size))
iv = b64encode(cipher.iv).decode('utf-8')
ct = b64encode(ct_bytes).decode('utf-8')
result = json.dumps({'iv':iv, 'ciphertext':ct})
print("")
print("MODO CBC")
print(result)

try:
    b64 = json.loads(result)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    print("The message was: ", pt.decode('utf-8'))
except:
    print("Incorrect decryption")
print(" ")


data = 'ejemplo sencillo para comprobar el segundo metodo de encripcion CTR'
datab = bytes(data, encoding='utf-8')

#MODO CTR
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CTR)
ct_bytes = cipher.encrypt(datab)
nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(ct_bytes).decode('utf-8')
result = json.dumps({'nonce':nonce, 'ciphertext':ct})
print("MODO CTR")
print(result)

try:
    b64 = json.loads(result)
    nonce = b64decode(b64['nonce'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    pt = cipher.decrypt(ct)
    print("The message was: ", pt.decode('utf-8'))
except:
    print("Incorrect decryption")
print(" ")

data = 'ejemplo sencillo para comprobar el terce metodo de encripcion CFB'
datab = bytes(data, encoding='utf-8')

#MODO CFB
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CFB)
ct_bytes = cipher.encrypt(datab)
iv = b64encode(cipher.iv).decode('utf-8')
ct = b64encode(ct_bytes).decode('utf-8')
result = json.dumps({'iv':iv, 'ciphertext':ct})
print("MODO CFB")
print(result)

try:
    b64 = json.loads(result)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    pt = cipher.decrypt(ct)
    print("The message was: ", pt.decode('utf-8'))
except:
    print("Incorrect decryption")