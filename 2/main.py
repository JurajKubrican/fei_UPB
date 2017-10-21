import os
import struct

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA

chunksize = 1024 * 64
in_dir = 'in/'
enc_dir = 'enc/'
dec_dir = 'dec/'
file = 'img.jpg'

KEY_LENGTH = 1024

file_key_length = 128




def pad16(data):
    if (len(data) % 16 == 0):
        return data
    return data + b'=' * (16 - len(data) % 16)



def genKeys():
    random_gen = Random.new().read
    private_key = RSA.generate(KEY_LENGTH, random_gen)

    if(os.path.exists('keys/key')==0):
        file = open('keys/key', 'wb')
        file.write(private_key.exportKey())
        file = open('keys/key.pub', 'wb')
        file.write(private_key.publickey().exportKey())

genKeys()


def enc_RSA(message):
    file = open('keys/key.pub')
    pub_key = file.read()
    key = RSA.importKey(pub_key)
    print(key)
    return key.encrypt(message, 32)


def dec_RSA(encrypted):

    file = open('keys/key')
    pub_key = file.read()
    key = RSA.importKey(pub_key)
    return key.decrypt(encrypted)

def encrypt(file_name):
    key = Random.new().read(16)
    iv = Random.new().read(AES.block_size)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    infile = open(in_dir + file_name, 'rb')
    filesize = os.path.getsize(in_dir + file_name)

    # print(b'key: ' + key)
    # print(b'iv: ' + iv)
    # print('size: ' + str(filesize))

    outfile = open(enc_dir + file_name, 'wb')

    encrypted_key = enc_RSA(key)
    outfile.write(struct.pack('<Q', filesize))
    outfile.write(iv)
    outfile.write(encrypted_key[0])

    print('encrypting')
    while True:
        print('.', end="")
        chunk = infile.read(chunksize)
        if (len(chunk) == 0):
            break
        chunk = pad16(chunk)
        outfile.write(cipher.encrypt(chunk))



encrypt(file)


def decrypt(file_name):
    infile = open(enc_dir + file_name, 'rb')
    rawfilesize = infile.read(struct.calcsize('Q'))
    filesize = struct.unpack('<Q', rawfilesize)[0]
    iv = infile.read(AES.block_size)
    key = infile.read(file_key_length)
    key = dec_RSA(key)

    # print(b'key: ' + key)
    # print('size: ' + str(filesize))
    # print(b'iv: ' + iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    outfile = open(dec_dir + file_name, 'wb')
    print('decrypting')
    while True:
        print('.', end="")
        chunk = infile.read(chunksize)
        if len(chunk) == 0:
            break
        outfile.write(cipher.decrypt(chunk))

    outfile.truncate(filesize)


decrypt(file)
