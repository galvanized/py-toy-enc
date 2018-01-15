import secrets
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_512
from Crypto.Util.Padding import *
from Crypto.Protocol.KDF import scrypt
import os.path
import timeit

'''
Toy Encryption
(actually works but don't sue me please)

Storage format:
|-----|---------|----------|---------------------------------|
   |       |          |                      |
  salt    hash     filename                 data
B: 32      64        256                 16-padded


Build exe on windows with
 python "C:\Program Files\Python36\Scripts\cxfreeze" toyenc.py --target-dir dist -OO -c
 (install cxfreeze first)
'''

# scrypt parameters
N = 2**21 #will take 2GB ram
r = 8
p = 8

def benchmark():
    iters = 2**16
    start_time = timeit.default_timer()
    scrypt(password='password', salt=secrets.token_bytes(32), key_len=32, N=iters, r=r, p=p)
    elapsed = timeit.default_timer() - start_time
    predicted = elapsed * N / iters

    print("Key derivation will take about {} seconds ({} per second).".format(
        round(predicted, 2), round(1/predicted, 3)
        ))

def encrypt(inpath, outpath, password):
    filename = os.path.basename(inpath)
    salt = secrets.token_bytes(32)
    print("Deriving key.")
    key = scrypt(password=password, salt=salt, key_len=32, N=N, r=r, p=p)

    print("Reading file.")
    with open(inpath, 'rb') as inf:
        in_data = pad(inf.read(), 16)

    print("Encrypting.")
    e = AES.new(key, AES.MODE_ECB)
    out_data = e.encrypt(in_data)
    #EtM
    h = SHA3_512.new(key + out_data).digest()

    padded_filename = pad(filename.encode('utf-8')[:255], 256)
    e_filename = e.encrypt(padded_filename)

    print("Writing file.")
    with open(outpath, 'wb') as outf:
        outf.write(salt)
        outf.write(h)
        outf.write(e_filename)
        outf.write(out_data)

def decrypt(inpath, password):
    print("Reading file.")
    with open(inpath, 'rb') as inf:
        salt = inf.read(32)
        h_in = inf.read(64)
        e_filename = inf.read(256)
        in_data = inf.read()

    print("Deriving key.")
    key = scrypt(password=password, salt=salt, key_len=32, N=N, r=r, p=p)

    print("Decrypting.")

    h = SHA3_512.new(key + in_data).digest()
    if h != h_in:
        raise BadDecrypt

    e = AES.new(key, AES.MODE_ECB)
    filename = unpad(e.decrypt(e_filename), 256).decode('utf-8')
    print(filename)
    out_data = unpad(e.decrypt(in_data),16)

    with open(filename, 'wb') as outf:
        outf.write(out_data)

class BadDecrypt(Exception):
    pass

def get_name():
    fn = input("First name: ").strip().lower()
    ln = input("Last name: ").strip().lower()
    n = fn + ' ' + ln
    return n.encode('utf-8')

def encrypt_interactive(password):
    plain_file = input("Filename of unencrypted input: ")
    enc_file = input("Filename of encrypted output: ")

    encrypt(plain_file, enc_file, password)

def decrypt_interactive(password):
    enc_file = input("Filename of encrypted input: ")

    decrypt(enc_file, password)

def select_interactive(name_enabled=True):
    mode = None
    while mode!='enc' and mode!='dec':
        print("Please enter ENC or DEC.")
        mode = input("Encrypt or decrypt?: ").lower()
    print("Ok.\n")


    pwmode = None if name_enabled else 'no'
    while pwmode!='yes' and pwmode!='no':
        print("Please enter YES or NO.")
        pwmode = input("Use name as password?: ").lower()

    password = get_name() if pwmode == "yes" else input("Enter password: ")

    encrypt_interactive(password) if mode=='enc' else decrypt_interactive(password)



if __name__ == '__main__':
    benchmark()
    select_interactive(False)
