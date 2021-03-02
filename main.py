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


def make_key():
    # returns 16 random bytes
    # https://docs.python.org/3/library/secrets.html#module-secrets

    # uncomment this line to make it not random:
    # return bytes.fromhex("65f3028ab7b10f8f3967cdd721120df2")

    return secrets.token_bytes(16)


def make_iv():
    # returns 16 random bytes
    # https://docs.python.org/3/library/secrets.html#module-secrets
    
    # uncomment this line to make it not random:
    # return bytes.fromhex("4493735b6a50dffc7e0d04bd751c2927")
    
    return secrets.token_bytes(16)


def submit(input_val):
    global global_key, global_iv

    # URL encode ; to %3B and = to %3D
    input_val = input_val.replace(";", "%3B")
    input_val = input_val.replace("=", "%3D")

    # put other stuff
    input_val = "userid=456;userdata=" + input_val + ";session-id=31337"

    # change to byte array
    input_val = bytes(input_val, encoding="utf-8")

    # pad the string
    input_val = pad(input_val, 16)

    # encrypt using CBC and return
    encrypted_ciphertext = custom_cbc_encrypt(input_val, global_key, global_iv)
    return encrypted_ciphertext


def verify(input_val):
    d = custom_cbc_decrypt(input_val)
    if (d.find(";admin=true;") == -1):
        return False
    else:
        return True


def testTaskI():
    global global_key, global_iv

    """ ECB encryption"""
    # open image
    img = Image.open('/Users/krdixson/Desktop/321/BlockCipher/cp-logo.bmp')

    # convert to byte stream
    img_hdr, img_bytes = bmp_to_bytes(img)

    print(blue, "ECB key:", global_key.hex(), end)

    # encrypt
    ciphertext_bytes = custom_ecb_encrypt(img_bytes, global_key)

    f = open("ECB_custom.bmp", "wb")
    f.write(img_hdr)
    f.write(ciphertext_bytes)
    f.close()
    
    """ CBC encryption"""
    # open image
    img = Image.open('/Users/krdixson/Desktop/321/BlockCipher/cp-logo.bmp')

    # convert to byte stream
    img_hdr, img_bytes = bmp_to_bytes(img)

    print(blue, "CBC key:", global_key.hex(), end)
    print(purple, "CBC IV:", global_iv.hex(), end)

    # encrypt
    ciphertext_bytes = custom_cbc_encrypt(img_bytes, global_key, global_iv)

    f = open("CBC_custom.bmp", "wb")
    f.write(img_hdr)
    f.write(ciphertext_bytes)
    f.close()


def testTaskII():
    submit("You're the man now, dog")
    submit("You're the man now; =, ; = dog")
    

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


def custom_cbc_encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    xor_blk = xor_byte_arrays(data[0:16], iv)

    encrypted_block = cipher.encrypt(xor_blk)
    ciphertext_bytes = encrypted_block
    previous_block = encrypted_block

    num_iters = (len(data) // 16) * 16

    for i in range(16, num_iters, 16):
        block = data[i: i + 16]
        xord_block = xor_byte_arrays(previous_block, block)
        encrypted = cipher.encrypt(xord_block)
        ciphertext_bytes += encrypted
        previous_block = encrypted

    if len(data) % 16 != 0:
        block = pad(data[num_iters:], 16)
        xord_block = xor_byte_arrays(previous_block, block)
        encrypted = cipher.encrypt(xord_block)
        ciphertext_bytes += encrypted

    return ciphertext_bytes


def custom_cbc_decrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)

    encrypted_block = cipher.decrypt(data[0:16])
    plaintext_block = xor_byte_arrays(encrypted_block, iv)

    plaintext_bytes = plaintext_block
    previous_block = data[0:16]

    num_iters = (len(data) // 16) * 16

    for i in range(16, num_iters, 16):
        block = data[i: i + 16]
        decrypted = cipher.decrypt(block)
        plaintext_block = xor_byte_arrays(decrypted, previous_block)
        plaintext_bytes += plaintext_block
        previous_block = block

    if len(data) % 16 != 0:
        block = data[num_iters:]
        decrypted = cipher.decrypt(block)
        plaintext_block = xor_byte_arrays(decrypted, previous_block)
        plaintext_bytes += plaintext_block

    return plaintext_bytes


def custom_ecb_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_bytes = cipher.encrypt(data[0:16])

    num_iters = (len(data) // 16) * 16

    for i in range(16, num_iters, 16):
        block = data[i:i+16]
        ciphertext_bytes += cipher.encrypt(block)

    if len(data) % 16 != 0:
        ciphertext_bytes += cipher.encrypt(pad(data[num_iters:], 16))

    return ciphertext_bytes


def correct_ecb_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_bytes = cipher.encrypt(pad(data, 16))
    return ciphertext_bytes


def correct_cbc_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext_bytes = cipher.encrypt(pad(data, 16))
    return ciphertext_bytes


if __name__ == '__main__':
    global_key = make_key()
    global_iv = make_iv()

    # testTaskI()
    # testTaskII()

    ciph = custom_cbc_encrypt(bytes("hello cameron this is funny because camaron in spanish is shrimp lolololololol", encoding="utf-8"), global_key, global_iv)
    plain = custom_cbc_decrypt(ciph, global_key, global_iv)
    print(plain)
