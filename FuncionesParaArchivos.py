#Importamos las librerias a utilizar.
from Crypto import Random
from Crypto.Cipher import AES

#Conversion a Bytes 
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

#Funcion de encriptar con CBC normal.  
def encriptar(archivo, key, keySize=128):
    archivo = pad(archivo)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(archivo)

#Funcion de desencriptar con CBC normal.  
def desencriptar(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

#Funcion de encriptar archivos .txt con CBC.  
def encriptarArchivo(archivo, key):
    with open(archivo, 'rb') as file:
        plaintext = file.read()
    enc = encriptar(plaintext, key)
    with open(archivo + ".enc", 'wb') as file:
        file.write(enc)

#Funcion de desencriptar archivos .enc con CBC.  
def desencriptarArchivo(archivo, key):
    with open(archivo, 'rb') as file:
        ciphertext = file.read()
    dec = desencriptar(ciphertext, key)
    with open(archivo + ".dec", 'wb') as file:
        file.write(dec)

#Llave de 16 bytes
key = b'a9755fd70d8d6db65a6fac12d4797dde'
#encriptarArchivo('text.txt', key)
desencriptarArchivo('text.txt.enc', key)
