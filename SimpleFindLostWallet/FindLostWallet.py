import binascii
import binascii
import hashlib
import hmac
import struct
from ecdsa.curves import SECP256k1
import numpy as np
import io
import time
from eth_utils import to_checksum_address, keccak as eth_utils_keccak
import os
from bip_utils import (
    MnemonicChecksumError, Bip39Languages, Bip39WordsNum, Bip39Mnemonic,
    Bip39MnemonicGenerator, Bip39MnemonicValidator, Bip39MnemonicDecoder
)
from threading import Thread
import threading
from alive_progress import alive_bar

count = 0

def seedToKey(seed):
    BIP39_PBKDF2_ROUNDS = 2048
    BIP39_SALT_MODIFIER = "mnemonic"
    BIP32_PRIVDEV = 0x80000000
    BIP32_CURVE = SECP256k1
    BIP32_SEED_MODIFIER = b'Bitcoin seed'
    ETH_DERIVATION_PATH = "m/44'/60'/0'/0"
    mnemonic = seed

    class PublicKey:
        def __init__(self, private_key):
            self.point = int.from_bytes(
                private_key, byteorder='big') * BIP32_CURVE.generator

        def __bytes__(self):
            xstr = self.point.x().to_bytes(32, byteorder='big')
            parity = self.point.y() & 1
            return (2 + parity).to_bytes(1, byteorder='big') + xstr

        def address(self):
            x = self.point.x()
            y = self.point.y()
            s = x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
            return to_checksum_address(eth_utils_keccak(s)[12:])

    def mnemonic_to_bip39seed(mnemonic, passphrase):
        mnemonic = bytes(mnemonic, 'utf8')
        salt = bytes(BIP39_SALT_MODIFIER + passphrase, 'utf8')
        return hashlib.pbkdf2_hmac('sha512', mnemonic, salt, BIP39_PBKDF2_ROUNDS)

    def bip39seed_to_bip32masternode(seed):
        k = seed
        h = hmac.new(BIP32_SEED_MODIFIER, seed, hashlib.sha512).digest()
        key, chain_code = h[:32], h[32:]
        return key, chain_code

    def derive_bip32childkey(parent_key, parent_chain_code, i):
        assert len(parent_key) == 32
        assert len(parent_chain_code) == 32
        k = parent_chain_code
        if (i & BIP32_PRIVDEV) != 0:
            key = b'\x00' + parent_key
        else:
            key = bytes(PublicKey(parent_key))
        d = key + struct.pack('>L', i)
        while True:
            h = hmac.new(k, d, hashlib.sha512).digest()
            key, chain_code = h[:32], h[32:]
            a = int.from_bytes(key, byteorder='big')
            b = int.from_bytes(parent_key, byteorder='big')
            key = (a + b) % BIP32_CURVE.order
            if a < BIP32_CURVE.order and key != 0:
                key = key.to_bytes(32, byteorder='big')
                break
            d = b'\x01' + h[32:] + struct.pack('>L', i)
        return key, chain_code

    def parse_derivation_path(str_derivation_path):
        path = []
        if str_derivation_path[0:2] != 'm/':
            raise ValueError(
                "Can't recognize derivation path. It should look like \"m/44'/60/0'/0\".")
        for i in str_derivation_path.lstrip('m/').split('/'):
            if "'" in i:
                path.append(BIP32_PRIVDEV + int(i[:-1]))
            else:
                path.append(int(i))
        return path

    def mnemonic_to_private_key(mnemonic, str_derivation_path, passphrase=""):
        derivation_path = parse_derivation_path(str_derivation_path)
        bip39seed = mnemonic_to_bip39seed(mnemonic, passphrase)
        master_private_key, master_chain_code = bip39seed_to_bip32masternode(
            bip39seed)
        private_key, chain_code = master_private_key, master_chain_code
        for i in derivation_path:
            private_key, chain_code = derive_bip32childkey(
                private_key, chain_code, i)
        return private_key

    if __name__ == '__main__':
        import sys

        private_key = mnemonic_to_private_key(mnemonic,
                                              str_derivation_path=f'{ETH_DERIVATION_PATH}/0')
        public_key = PublicKey(private_key)

        privkey = binascii.hexlify(private_key).decode("utf-8")
        addressOfMemo = public_key.address()

        # print(f'privkey: {privkey}')
        # print(f'pubkey:  {address}')
        # print(f'address: {public_key.address()}')

        return privkey, addressOfMemo


def main(rangeNum1, rangeNum2):
    global count

    file1 = open('mnemonic.txt', 'r')
    Lines = file1.readlines()
    mneArr = []
    count = 0
    for line in Lines:
        count += 1
        mneArr.append(line.strip())

    x = range(rangeNum1, rangeNum2, 1)
    y = range(0, 2048, 1)

    print('Running! ', rangeNum1, ' ', rangeNum2)

    for n in x:
        seed = "surround barrel surround galaxy fine inch rural glide brass run"
        seed1 = seed + ' ' + mneArr[n]
        for i in y:
            seed2 = seed1 + ' ' + mneArr[i]
            privkey, address = seedToKey(seed2)
            # if mneArr[i] == 'keep':
            # print(address)
            # print(seed2)
            if address == "0xf5C31524ddac86439A6D0cd824F0C1988f44bcFF":
                print(f'Address: {address}')
                print(seed2)
                break
                # print(f'Address: {address}')
                # print("Count: ", i)
            count = count + 1
            print(f'\r{count}/4.194.304', sep=' ', end='', flush=True)



try:
    t=time.time()
    Threads = []
    n = 2048
    
    start = 0
    ranges = range(100,2000,100)

    for x in ranges:
        t=threading.Thread(target = main, args = (start, x,))
        Threads.append(t)
        start = start + 100

    t=threading.Thread(target = main, args = (2000, 2048,))
    Threads.append(t)    

    for x in Threads:
        x.start()
    for x in Threads:
        x.join()

    print("done in ", time.time() - t)

except:
    print("error")
