import sys
import os
import io
import secrets
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PIL import Image


def main():
    img = Image.open('/Users/krdixson/Desktop/321/BlockCipher/cp-logo.bmp')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format="BMP")
    img_bytes = img_bytes.getvalue()

    key = makeKey()
    print("key:", key.hex())

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_bytes = cipher.encrypt(img_bytes[0:16])

    for i in range(16, len(img_bytes) // 16, 16):
        block = img_bytes[i:i+16]
        ciphertext_bytes += cipher.encrypt(block)

    if len(img_bytes) % 16 != 0:
        ciphertext_bytes += cipher.encrypt(
            pad(img_bytes[len(img_bytes)//16+1 : ], 16))

    f = open("ECB.txt", "wb")
    f.write(ciphertext_bytes)
    f.close()

    # dont do this ----> print("\ncipher:", ciphertext_bytes.hex(), "\n")

    # https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html


def correct_output():
    img = Image.open('/Users/krdixson/Desktop/321/BlockCipher/cp-logo.bmp')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format="BMP")
    img_bytes = img_bytes.getvalue()

    key = makeKey()
    print("key:", key.hex())

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_bytes = cipher.encrypt(pad(img_bytes, 16))

    f = open("ECB_correct.txt", "wb")
    f.write(ciphertext_bytes)
    f.close()


def makeKey():
    # returns 16 random bytes
    # https://docs.python.org/3/library/secrets.html#module-secrets
    
    # uncomment this line to make it not random:
    # return bytes.fromhex("65f3028ab7b10f8f3967cdd721120df2")
    
    return secrets.token_bytes(16)


if __name__ == '__main__':
    main()
    correct_output()
