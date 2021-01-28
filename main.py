import sys
from Crypto.Cipher import AES

def main():

    data = b"1234567nnn890123456"
    key = b"Sixteen byte key"

    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    print("\ncipher:", ciphertext, "\n")

    # https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html

if __name__ == '__main__':
    main()