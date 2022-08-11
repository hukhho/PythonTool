from audioop import add
from ctypes import addressof
from re import X
from tkinter import Y
from unicodedata import decimal
from xml.dom import xmlbuilder
from pathlib import Path
import web3
from web3 import Web3
import binascii
import binascii, hashlib, hmac, struct
from ecdsa.curves import SECP256k1
from eth_utils import to_checksum_address, keccak as eth_utils_keccak
import json
import config
import numpy as np
import io
import time
import requests
from requests.structures import CaseInsensitiveDict
import os
import decimal
from dotenv import load_dotenv
from bip_utils import (
    MnemonicChecksumError, Bip39Languages, Bip39WordsNum, Bip39Mnemonic,
    Bip39MnemonicGenerator, Bip39MnemonicValidator, Bip39MnemonicDecoder
)
from web3.auto import w3

load_dotenv()

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
            self.point = int.from_bytes(private_key, byteorder='big') * BIP32_CURVE.generator

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
            raise ValueError("Can't recognize derivation path. It should look like \"m/44'/60/0'/0\".")
        for i in str_derivation_path.lstrip('m/').split('/'):
            if "'" in i:
                path.append(BIP32_PRIVDEV + int(i[:-1]))
            else:
                path.append(int(i))
        return path

    def mnemonic_to_private_key(mnemonic, str_derivation_path, passphrase=""):
        derivation_path = parse_derivation_path(str_derivation_path)
        bip39seed = mnemonic_to_bip39seed(mnemonic, passphrase)
        master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
        private_key, chain_code = master_private_key, master_chain_code
        for i in derivation_path:
            private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
        return private_key


    if __name__ == '__main__':
        import sys  
        private_key = mnemonic_to_private_key(mnemonic,
                str_derivation_path=f'{ETH_DERIVATION_PATH}/0')
        public_key = PublicKey(private_key)

        privkey = binascii.hexlify(private_key).decode("utf-8")
        addressOfMemo = public_key.address()

        #print(f'privkey: {privkey}')
        #print(f'pubkey:  {address}')
        #print(f'address: {public_key.address()}')
        
        return privkey, addressOfMemo;

def connectWeb3():
    bsc = "https://data-seed-prebsc-1-s1.binance.org:8545/"
    #bsc = "https://bsc-dataseed1.defibit.io/"
    web3 = Web3(Web3.HTTPProvider(bsc))
    seed = os.getenv('seed')
    privkey, address = seedToKey(seed)
    #print(f'Private key: {privkey}')
    print(f'\n----------------------------------Connecting WEB 3 ----------------------------------')
    print(f'\nConnecting To Address: {address} ----- Status: {web3.isConnected()}')
    if web3.isConnected() == 'True':
        print(">>>>>>CONNECTED>>>>>>\n")
    with open('panabi.json', 'r') as j:
        panabi = json.loads(j.read())       
    with open('bep20.json', 'r') as j:
        bep20 = json.loads(j.read())    
    with open('x8ABI.json', 'r') as j:
        x8abi = json.loads(j.read())   
    with open('sellAbi.json', 'r') as j:
        sellAbi = json.loads(j.read()) 
    with open('petCoreABI.json', 'r') as j:
        petCoreABI = json.loads(j.read()) 
    
    balanceCheck = web3.eth.get_balance(address)
    humanReadable = web3.fromWei(balanceCheck,'ether')
    print(f"Address {address}: {humanReadable} BNB")
    print("\n\n")
    
    return web3, panabi, bep20, address, privkey;

def writeABI():
    sellAbi = ''
    contents = json.dumps(sellAbi)
    jsonFile = open("sellAbi.json", "w")
    jsonFile.write(contents)
    jsonFile.close()

def buyToken(panabi, tokenAbi, buyTokenAdd, addressOfMne, privkey, web3, amount, mintoken, revice):
    #panRouterContractAddress = '0xD99D1c33F9fC3444f8101754aBC46c52416550D1' TEST
    #panRouterContractAddress = '0x10ED43C718714eb63d5aA57B78B54704E256024E'
    panRouterContractAddress = '0xD99D1c33F9fC3444f8101754aBC46c52416550D1' #https://bsc.kiemtienonline360.com/
    sender_address = addressOfMne
    tokenToBuy = web3.toChecksumAddress(buyTokenAdd)            #web3.toChecksumAddress("0x6615a63c260be84974166a5eddff223ce292cf3d")
    spend = web3.toChecksumAddress("0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd")  #wbnb contract #wbnb0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd TEST
    #Setup the PancakeSwap contract
    contract = web3.eth.contract(address=panRouterContractAddress, abi=panabi)

    tokencontract = web3.eth.contract(address=tokenToBuy, abi=tokenAbi)

    decim =  tokencontract.functions.decimals().call()
    tokenName =  tokencontract.functions.name().call()

    print(f'Token name: {tokenName} Decimal: {decim}')

    nonce = web3.eth.get_transaction_count(sender_address)
    start = time.time()
    pancakeswap2_txn = contract.functions.swapExactETHForTokens(
    mintoken * 10**decim, # set to 0, or specify minimum amount of tokeny you want to receive - consider decimals!!!
    [spend,tokenToBuy],
    revice,
    (int(time.time()) + 60*5)
    ).buildTransaction({
    'from': sender_address,
    'value': web3.toWei(amount,'ether'),#This is the Token(BNB) amount you want to Swap from
    'gas': 1000000,
    'gasPrice': web3.toWei('21','gwei'),
    'nonce': nonce,
    })

    #receipt = web3.eth.waitForTransactionReceipt(pancakeswap2_txn)
    #print(receipt)
    signed_txn = web3.eth.account.sign_transaction(pancakeswap2_txn, private_key=privkey)
    tx_token = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    tx_hash = web3.toHex(tx_token)
    #print("Bought: ", tx_hash)

    #tx = web3.eth.get_transaction(web3.toHex(tx_token))
    #print(tx)
    
    receipt = web3.eth.waitForTransactionReceipt(web3.toHex(tx_token), timeout=600)
    
    status = receipt['status']
    print(f'---->TxHash: {tx_hash} - Status: {status}')

    print(f"https://testnet.bscscan.com/tx/{tx_hash}")
    #print(f"https://bscscan.com/tx/{tx_hash}")
    print("\n\n")
   
    return tx_hash, status;

def sellToken(panabi, tokenAbi, tokenToSell, addressOfMne, privkey, web3, amountTokenSell, minOut, revice):
    #panRouterContractAddress = '0xD99D1c33F9fC3444f8101754aBC46c52416550D1' TEST
    #panRouterContractAddress = '0x10ED43C718714eb63d5aA57B78B54704E256024E'
    panRouterContractAddress = '0xD99D1c33F9fC3444f8101754aBC46c52416550D1' #https://bsc.kiemtienonline360.com/
    sender_address = addressOfMne
    tokenToSell = web3.toChecksumAddress(tokenToSell)            #web3.toChecksumAddress("0x6615a63c260be84974166a5eddff223ce292cf3d")
    wBNB = web3.toChecksumAddress("0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd")  #wbnb contract #wbnb0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd TEST
    #Setup the PancakeSwap contract
    contract = web3.eth.contract(address=panRouterContractAddress, abi=panabi)
    
    tokencontract = web3.eth.contract(address=tokenToSell, abi=tokenAbi)
  
    decim =  tokencontract.functions.decimals().call()
    tokenName =  tokencontract.functions.name().call()
    balanceToken = tokencontract.functions.balanceOf(sender_address).call()
    balanceTokenRead = balanceToken/(10**decim)
    
    minOut = web3.toWei(minOut, 'ether')
    print(f'Token name: {tokenName} Decimal: {decim}  Balance: {balanceTokenRead}' )

    amountTokenSell = amountTokenSell * (10**decim) 

    nonce = web3.eth.get_transaction_count(sender_address)
    start = time.time()
    
    pancakeswap2_txn = contract.functions.swapExactTokensForETH(      
    int(amountTokenSell), # set to 0, or specify minimum amount of tokeny you want to receive - consider decimals!!!
    minOut,
    [tokenToSell,wBNB],
    revice,
    (int(time.time()) + 60*5)
    ).buildTransaction({
    'from': sender_address,
    'gas': 1000000,
    'gasPrice': web3.toWei('21','gwei'),
    'nonce': nonce,
    })

    signed_txn = web3.eth.account.sign_transaction(pancakeswap2_txn, private_key=privkey)
    tx_token = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    tx_hash = web3.toHex(tx_token)
    
    receipt = web3.eth.waitForTransactionReceipt(web3.toHex(tx_token), timeout=600)
    status = receipt['status']

   
    balanceToken_after = tokencontract.functions.balanceOf(sender_address).call()
    balanceTokenRead_after = balanceToken_after/(10**decim)
    balanceToken_change = balanceToken_after - balanceToken
    

    print(f'---->TxHash: {tx_hash} - Status: {status}')
    if status == 1:
        print(f'Sell success {balanceToken_change}')
        print(f'Token name: {tokenName} Decimal: {decim}  Balance: {balanceTokenRead_after}' )
    print(f"https://testnet.bscscan.com/tx/{tx_hash}")
    #print(f"https://bscscan.com/tx/{tx_hash}")
    print("\n\n")

   
    return tx_hash, status;

def main():

    web3, panabi, bep20, addressOfMne, privkey = connectWeb3();

    BUSD_test = '0x78867BbEeF44f2326bF8DDd1941a4439382EF2A7'
    tokenBuy = '0xE02dF9e3e622DeBdD69fb838bB799E3F168902c5'

    revice = web3.toChecksumAddress(addressOfMne)
    tokenAddress = web3.toChecksumAddress(tokenBuy)

    buyamount = 0.01
    minbuy = 0
    try:        
        tx_hash, status = buyToken(panabi, bep20, tokenAddress, addressOfMne, privkey, web3, buyamount, minbuy, revice)
        if status == 0:
            print('Buy Not SUCCESS!!!!!!!')
        if status == 1:
            print(f'Buy token Success !!!! {tx_hash}') 

    except Exception as e:
        print('--->EXCEPT e: \n')
        print (e)

    balanceCheck = web3.eth.get_balance(addressOfMne)
    humanReadable = web3.fromWei(balanceCheck,'ether')
    print(f"Address {addressOfMne}: {humanReadable} BNB\n")


    amountTokenSell = 2
    minOut = 0
    try:        
        tx_hash, status = sellToken(panabi, bep20 , tokenBuy, addressOfMne, privkey, web3, amountTokenSell, minOut, revice)
        if status == 0:
            print('Sell Not SUCCESS!!!!!!!')
        if status == 1:
            print(f'Sell token Success !!!! {tx_hash}') 
    except Exception as e:
        print('--->EXCEPT e: \n')
        print (e)

    balanceCheck = web3.eth.get_balance(addressOfMne)
    humanReadable = web3.fromWei(balanceCheck,'ether')
    print(f"Address {addressOfMne}: {humanReadable} BNB\n")

def main2():
    web3, panabi, bep20, addressOfMne, privkey = connectWeb3();
    balanceCheck = web3.eth.get_balance(addressOfMne)
    humanReadable = web3.fromWei(balanceCheck,'ether')
    print(f"Address {addressOfMne}: {humanReadable} BNB\n")



    l = web3.eth.filter('latest')
    while True:
        ts1 = time.time()
        ll = l.get_new_entries()
        for i in ll:
            print('===== Block hash:  ', i.hex())
            block_hash = i.hex()
            block = web3.eth.getBlock(block_hash, full_transactions=True)
            transactions = block['transactions']
            print('===== Block Number: ', block['number'])
            for tx in transactions:
                print(ts1, '   From wallet: ', tx['from'])
                print(ts1, '   Value ETH: ', tx['value'])
main()










