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
    ciphertext_bytes = cipher.encrypt(pad(img_bytes, AES.block_size))

    f = open("ciphahhh.txt", "wb")
    f.write(ciphertext_bytes)
    f.close()

    # dont do this ----> print("\ncipher:", ciphertext_bytes.hex(), "\n")

    # https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html


def makeKey():
    # returns 16 random bytes
    # https://docs.python.org/3/library/secrets.html#module-secrets
    return secrets.token_bytes(16)


if __name__ == '__main__':
    main()
