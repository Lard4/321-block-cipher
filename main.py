import io
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PIL import Image
import binascii


red = "\x1B[31m"
green = "\x1B[32m"
blue = "\x1B[34m"
yellow = "\x1B[33m"
purple = "\x1B[35m"
end = "\x1B[0m"


def bmp_to_bytes(img):
    # convert to byte stream
    img_bytes = io.BytesIO()
    img.save(img_bytes, format="BMP")
    img_bytes = img_bytes.getvalue()

    # save header and skip over it
    img_hdr = img_bytes[0:54]
    img_bytes = img_bytes[54:]

    return img_hdr, img_bytes


def xor_byte_arrays(one, two):
    return bytes(a ^ b for (a, b) in zip(one, two))


def custom_cbc():
    # open image
    img = Image.open('/Users/krdixson/Desktop/321/BlockCipher/cp-logo.bmp')
    #img = Image.open('/Users/cameronpriest/Desktop/Winter Quarter/CPE 321/Assignments/blockciphers/cp-logo.bmp')

    # convert to byte stream
    img_hdr, img_bytes = bmp_to_bytes(img)

    # make the byte array mutable
    img_bytes = bytearray(img_bytes)

    key = make_key()
    print("key:", key.hex())

    iv = make_key()
    print("IV:", iv.hex())

    cipher = AES.new(key, AES.MODE_ECB)
    img_bytes[0:16] = xor_byte_arrays(key, iv)
    print(binascii.hexlify(img_bytes[0:16]))
    encrypted_block = cipher.encrypt(img_bytes[0:16])
    ciphertext_bytes = encrypted_block

    """previous_block = encrypted_block
    for i in range(16, len(img_bytes) // 16, 16):
        block = img_bytes[i:i+16]
        xord_block = xor_iv_with_input(key, previous_block, img_bytes, i, i+16)
        encrypted = cipher.encrypt(xord_block)
        ciphertext_bytes += encrypted
        previous_block = encrypted"""

    """if len(img_bytes) % 16 != 0:
        ciphertext_bytes += cipher.encrypt(
            pad(img_bytes[len(img_bytes)//16+1:], 16))"""

    f = open("CBC_custom.bmp", "wb")
    f.write(img_hdr)
    f.write(ciphertext_bytes)
    f.close()

def custom_ecb():
    # open image
    img = Image.open('/Users/krdixson/Desktop/321/BlockCipher/cp-logo.bmp')
    #img = Image.open('/Users/cameronpriest/Desktop/Winter Quarter/CPE 321/Assignments/blockciphers/cp-logo.bmp')
    
    # convert to byte stream
    img_hdr, img_bytes = bmp_to_bytes(img)

    key = make_key()
    print("key:", key.hex())

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_bytes = cipher.encrypt(img_bytes[0:16])

    for i in range(16, len(img_bytes) // 16, 16):
        block = img_bytes[i:i+16]
        ciphertext_bytes += cipher.encrypt(block)

    if len(img_bytes) % 16 != 0:
        ciphertext_bytes += cipher.encrypt(
            pad(img_bytes[len(img_bytes)//16+1 : ], 16))

    f = open("ECB_custom.bmp", "wb")
    f.write(img_hdr)
    f.write(ciphertext_bytes)
    f.close()


def correct_ecb():
    # open image
    img = Image.open('/Users/krdixson/Desktop/321/BlockCipher/cp-logo.bmp')
    #img = Image.open('/Users/cameronpriest/Desktop/Winter Quarter/CPE 321/Assignments/blockciphers/cp-logo.bmp')

    # convert to byte stream
    img_hdr, img_bytes = bmp_to_bytes(img)

    key = make_key()
    print("key:", key.hex())

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_bytes = cipher.encrypt(pad(img_bytes, 16))

    f = open("ECB_correct.bmp", "wb")
    f.write(img_hdr)
    f.write(ciphertext_bytes)
    f.close()


def correct_cbc():
    # open image
    img = Image.open('/Users/krdixson/Desktop/321/BlockCipher/cp-logo.bmp')
    # img = Image.open('/Users/cameronpriest/Desktop/Winter Quarter/CPE 321/Assignments/blockciphers/cp-logo.bmp')

    # convert to byte stream
    img_hdr, img_bytes = bmp_to_bytes(img)

    key = make_key()
    print("key:", key.hex())

    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext_bytes = cipher.encrypt(pad(img_bytes, 16))

    f = open("CBC_correct.bmp", "wb")
    f.write(img_hdr)
    f.write(ciphertext_bytes)
    f.close()


def make_key():
    # returns 16 random bytes
    # https://docs.python.org/3/library/secrets.html#module-secrets
    
    # uncomment this line to make it not random:
    # return bytes.fromhex("65f3028ab7b10f8f3967cdd721120df2")
    
    return secrets.token_bytes(16)


if __name__ == '__main__':
    # ECB
    # custom_ecb()
    # correct_ecb()
    
    # CBC
    custom_cbc()
    correct_cbc()


