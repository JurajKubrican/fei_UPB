import os
import struct
import sys
import hashlib
import pickle

from datetime import datetime
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA

chunksize = 1024 * 64

KEY_LENGTH = 1024

file_key_length = 128


def dec_filename(path):
    dir_name = os.path.dirname(path)
    file_name = os.path.basename(path)
    file_name = 'dec-' + file_name.replace('.enc', '')
    if (len(dir_name)):
        return dir_name + '/' + file_name
    return file_name


def sign(filename, signature_file, key_file):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(chunksize), b''):
            sha256.update(block)

    file = open(key_file)
    key = RSA.importKey(file.read())

    checksum = sha256.hexdigest().encode('utf-8')
    signature = key.sign(checksum, '')
    pickle.dump(signature, open(signature_file, 'wb'))


def verify(filename, signature_file, private_key):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(chunksize), b''):
            sha256.update(block)

    signature = pickle.load(open(signature_file, 'rb'))

    checksum = sha256.hexdigest().encode('utf-8')
    pub_key = open(private_key).read()
    key = RSA.importKey(pub_key).publickey()
    return key.verify(checksum, signature)


def pad16(data):
    if (len(data) % 16 == 0):
        return data
    return data + b'=' * (16 - len(data) % 16)


def genKeys(key_file):
    random_gen = Random.new().read
    private_key = RSA.generate(KEY_LENGTH, random_gen)

    file = open(key_file, 'wb')
    file.write(private_key.exportKey())
    file = open(key_file + '.pub', 'wb')
    file.write(private_key.publickey().exportKey())


def enc_RSA(message, public_key):
    file = open(public_key)
    pub_key = file.read()
    key = RSA.importKey(pub_key)
    return key.encrypt(message, 32)


def dec_RSA(encrypted, private_key):
    file = open(private_key)
    pub_key = file.read()
    key = RSA.importKey(pub_key)
    return key.decrypt(encrypted)


def encrypt(file_name, sender_private, receiver_public):
    time = datetime.now()
    key = Random.new().read(16)
    iv = Random.new().read(AES.block_size)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    infile = open(file_name, 'rb')
    filesize = os.path.getsize(file_name)

    outfile = open(file_name + '.enc', 'wb')

    encrypted_key = enc_RSA(key, receiver_public)
    outfile.write(struct.pack('<Q', filesize))
    outfile.write(iv)
    outfile.write(encrypted_key[0])

    print('encrypting', end="")
    while True:
        print('.', end="")
        chunk = infile.read(chunksize)
        if (len(chunk) == 0):
            break
        chunk = pad16(chunk)
        outfile.write(cipher.encrypt(chunk))

    sign(file_name + '.enc', file_name + '.sign', sender_private)

    print()
    print('Finished, took: ', end='')
    print(datetime.now() - time, end="\n")


def decrypt(file_name, sender_public, receiver_private):
    time = datetime.now()
    signature_file = file_name.replace('.enc', '.sign')
    if (verify(file_name, signature_file, sender_public) == 0):
        print('Message not verified!! exitting')
        return

    infile = open(file_name, 'rb')
    rawfilesize = infile.read(struct.calcsize('Q'))
    filesize = struct.unpack('<Q', rawfilesize)[0]
    iv = infile.read(AES.block_size)
    key = infile.read(file_key_length)
    key = dec_RSA(key, receiver_private)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    outfile = open(dec_filename(file_name), 'wb')
    print('decrypting', end="")
    while True:
        print('.', end="")
        chunk = infile.read(chunksize)
        if len(chunk) == 0:
            break
        outfile.write(cipher.decrypt(chunk))

    outfile.truncate(filesize)
    print()
    print('Finished, took: ', end='')
    print(datetime.now() - time, end="\n")


def main():
    if len(sys.argv) > 1:
        mode = sys.argv[1].upper()
        if mode == "G":
            if (len(sys.argv) == 3):
                genKeys(sys.argv[2])
                print("Key pair " + sys.argv[2] + " has been generated")
            else:
                print('usage: main.py G [key_name]')
        elif mode == "E":
            if (len(sys.argv) == 5):
                encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
            else:
                print('usage: main.py E [filename] [sender_private_key] [receiver_public_key]')
        elif mode == "D":
            if (len(sys.argv) == 5):
                decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
            else:
                print('usage: main.py  [filename] [sender_public_key] [receiver_private_key]')
        else:
            print("Available modes: [G E D]")
            print("mode G: generate key pair")
            print("mode E: encrypt")
            print("mode D: decrypt")
            print("for help enter main.py [mode]")

    else:
        print("Available modes: [G E D]")
        print("mode G: generate key pair")
        print("mode E: encrypt")
        print("mode D: decrypt")
        print("for help enter main.py [mode]")


if __name__ == "__main__":
    main()
