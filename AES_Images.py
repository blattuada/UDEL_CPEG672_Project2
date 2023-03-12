import binascii, hashlib
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import AES
from PIL import Image

# Encryption function to open an image, encrypt it using AES_ECB. 
def ImageECGEncryptDecrypt():
    # Open image, save bytes, print size/mode
    im_enc = Image.open("osrsbot.png")
    bytesIm = im_enc.tobytes()
    print(im_enc.size)
    print(im_enc.mode)

    # Define/print key. Create cipher in ECB mode and run encrypt. 
    # Use frombytes and previous image mode/size to create the encrypted PNG. 
    key = (b'706D6F6E696275797663747278657A77')
    print(key)
    cipher_ECB_enc=AES.new(key, AES.MODE_ECB)
    Image.frombytes(im_enc.mode, im_enc.size, cipher_ECB_enc.encrypt(bytesIm)).save('ECB_encrypted.png')

    # Open image, save bytes, print size/mode
    im_dec = Image.open("ECB_encrypted.png")
    bytesEnc = im_dec.tobytes()
    print(im_dec.size)
    print(im_dec.mode)

    # Using same cipher decrypt the encrypted bytes and save to a PNG. 
    Image.frombytes(im_dec.mode, im_dec.size, cipher_ECB_enc.decrypt(bytesEnc)).save('ECB_decrypted.png')

#ImageECGEncryptDecrypt()

# Decrytping ECG from another source/student. 
def ImageECGDecrypt():
    # Open image, save bytes, print size/mode
    im_dec = Image.open("encrypted.png")   
    bytes = im_dec.tobytes()
    print(im_dec.size)
    print(im_dec.mode)

    # Define/print key. Create cipher in ECB mode and run encrypt. 
    # Use frombytes and previous image mode/size to create the encrypted PNG. 
    key = binascii.unhexlify(b'686176656e7420646563696465642079')
    cipher_ECB_dec=AES.new(key, AES.MODE_ECB)
    Image.frombytes(im_dec.mode, im_dec.size, cipher_ECB_dec.decrypt(pad(bytes, 16))).save('Decrypt_test_yamen.png')

#ImageECGDecrypt()

# Ecnrypt in CBC mode. 
def ImageCBCEncrypt():
    # Open image, save bytes, print size/mode
    im_enc = Image.open("osrsbot.png")
    bytesIm = im_enc.tobytes()
    print(im_enc.size)
    print(im_enc.mode)

    # Define/print key. Create cipher in CBC mode using a defined IV and run encrypt. 
    # Use frombytes and previous image mode/size to create the encrypted PNG. 
    key = (b'706D6F6E696275797663747278657A77')
    print(key)
    cipher_CBC=AES.new(key, AES.MODE_CBC, b'696E697476637472')
    Image.frombytes(im_enc.mode, im_enc.size, cipher_CBC.encrypt(pad(bytesIm,16))).save('CBC_encrypted.png')

#ImageCBCEncrypt()

# Decrypt in CBC mode. 
def ImageCBCDecrypt():
    # Define/print key. Create cipher in CBC mode using a defined IV. 
    key = (b'706D6F6E696275797663747278657A77')
    cipher_CBC=AES.new(key, AES.MODE_CBC, b'696E697476637472')

    # Open image, save bytes and run decrypt on the encrypted image. 
    im_dec = Image.open("CBC_encrypted.png")
    print(im_dec.size)
    print(im_dec.mode)
    bytesEnc = im_dec.tobytes()
    Image.frombytes(im_dec.mode, im_dec.size, cipher_CBC.decrypt(pad(bytesEnc,16))).save('CBC_decrypt_test.png')

#ImageCBCDecrypt()

def ImageCTREnc():
    key = (b'706D6F6E696275797663747278657A77')
    cipher_CTR=AES.new(key, AES.MODE_CTR, nonce=b'6E6F6E6365')

    im_enc = Image.open("osrsbot.png")
    print(im_enc.size)
    print(im_enc.mode)
    bytesEnc = im_enc.tobytes()
    Image.frombytes(im_enc.mode, im_enc.size, cipher_CTR.decrypt(bytesEnc)).save('CTR_encrypt_test.png')

    im_dec = Image.open("CTR_encrypt_test.png")
    print(im_dec.size)
    print(im_dec.mode)
    bytesDec = im_dec.tobytes()
    Image.frombytes(im_dec.mode, im_dec.size, cipher_CTR.decrypt(bytesDec)).save('CTR_decrypt_test.png')

#ImageCTREnc()

def ImageCTRDec():
    key = (b'706D6F6E696275797663747278657A77')
    cipher_CTR=AES.new(key, AES.MODE_CTR, nonce=b'6E6F6E6365')

    im_dec = Image.open("CTR_encrypt_test.png")
    print(im_dec.size)
    print(im_dec.mode)
    bytesDec = im_dec.tobytes()
    Image.frombytes(im_dec.mode, im_dec.size, cipher_CTR.decrypt(bytesDec)).save('CTR_decrypt_test.png')

#ImageCTRDec()
