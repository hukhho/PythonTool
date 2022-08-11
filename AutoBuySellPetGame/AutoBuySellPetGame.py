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

def getPetInfo(petID):   

    url = "https://backend.agoran.io/query"

    headers = CaseInsensitiveDict()
    headers["accept"] = "*/*"
    headers["accept-encoding"] = "gzip, deflate, br"
    headers["accept-language"] = "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5"
    headers["content-length"] = "775"
    headers["Content-Type"] = "application/json"
    headers["origin"] = "https://marketplace-v1.mydefipet.com"
    headers["referer"] = "https://marketplace-v1.mydefipet.com/"
    headers["sec-ch-ua"] = '" Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"'
    headers["sec-ch-ua-mobile"] = "?0"
    headers["sec-ch-ua-platform"] = '"Windows"'
    headers["sec-fetch-dest"] = "empty"
    headers["sec-fetch-mode"] = "cors"
    headers["sec-fetch-site"] = "cross-site"
    headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36"

    data = '{"operationName":"getDPet","variables":{"where":{"tokenId":"3334422","blockChainId":"bsc"}},"query":"query getDPet($where: QueryDPetInputV1) {\n  dPetPetItemV1(where: $where) {\n    tokenId\n    stage\n    petType\n    rarityLevel\n    element\n    listingItem {\n      status\n      saleType\n      sellerAddress\n      marketplaceAddress\n      saleId\n      buyNowPrice\n      currentPrice\n      createdAt\n      updatedAt\n      __typename\n    }\n    nftOwnershipItem {\n      ownerAddress\n      __typename\n    }\n    transactionItem {\n      value\n      __typename\n    }\n    offers {\n      value\n      status\n      type\n      __typename\n    }\n    __typename\n  }\n}\n"}'
    data = data.replace("3334422", petID)
    data_1 = data.replace("\n", " ")

    resp = requests.post(url, headers=headers, data=data_1)
    #print(resp.content)
    json_data = json.loads(resp.text)
    print(json_data)

    i = json_data["data"]
    ii = i["dPetPetItemV1"]
    tokenID = ii["tokenId"]   
    stage = ii["stage"] 
    petType = ii["petType"]
    rarityLevel = ii["rarityLevel"]
    
    return tokenID, stage, petType, rarityLevel;

def getPetList2(owner):   
    url = "https://backend.agoran.io/query"

    headers = CaseInsensitiveDict()
    headers["accept"] = "*/*"
    headers["accept-encoding"] = "gzip, deflate, br"
    headers["accept-language"] = "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5"
    headers["content-length"] = "775"
    headers["Content-Type"] = "application/json"
    headers["origin"] = "https://marketplace-v1.mydefipet.com"
    headers["referer"] = "https://marketplace-v1.mydefipet.com/"
    headers["sec-ch-ua"] = '" Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"'
    headers["sec-ch-ua-mobile"] = "?0"
    headers["sec-ch-ua-platform"] = '"Windows"'
    headers["sec-fetch-dest"] = "empty"
    headers["sec-fetch-mode"] = "cors"
    headers["sec-fetch-site"] = "cross-site"
    headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36"

    data = '{"operationName":"getDPets","variables":{"orderBy":"token_id","orderDirection":"desc","offset":0,"limit":1000,"where":{"blockChainId":"bsc","saleStatus":["ONGOING"],"ownerAddress":"0x67c4109e6e2aa408c38de5b738867980784fc0df"}},"query":"query getDPets($orderBy: String, $orderDirection: OrderDirection, $limit: Int, $offset: Int, $where: QueryDPetInputV1) {\n  dPetPetItemsV1(\n    orderBy: $orderBy\n    orderDirection: $orderDirection\n    limit: $limit\n    offset: $offset\n    where: $where\n  ) {\n    count\n    data {\n      id\n      tokenId\n      stage\n      petType\n      rarityLevel\n      element\n      listingItem {\n        status\n        saleType\n        sellerAddress\n        marketplaceAddress\n        saleId\n        buyNowPrice\n        currentPrice\n        createdAt\n        updatedAt\n        __typename\n      }\n      transactionItem {\n        value\n        __typename\n      }\n      nftOwnershipItem {\n        ownerAddress\n        __typename\n      }\n      offers {\n        value\n        status\n        type\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"}'
    data = data.replace("0x67c4109e6e2aa408c38de5b738867980784fc0df", owner)
    data_1 = data.replace("\n", " ")

    resp = requests.post(url, headers=headers, data=data_1)
    #print(resp.content)
    json_data = json.loads(resp.text)
    i = json_data["data"]
    ii = i["dPetPetItemsV1"]
    iii = ii["data"]       
   
    arr2 = []
    for x in iii:
        iiii = x["tokenId"]
        stage = x["stage"]
        arr2.append(int(iiii));              
    return arr2;

def getPetList(petCoreAddress, owner, web3):

    balance = web3.eth.get_balance(owner)
    print(web3.fromWei(balance, 'ether'))
    contract_address = petCoreAddress
    abi = json.loads('[{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"owner","type":"address"},{"indexed":false,"internalType":"address","name":"approved","type":"address"},{"indexed":false,"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"owner","type":"address"},{"indexed":false,"internalType":"uint256","name":"PetId","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"matronId","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"sireId","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"genes","type":"uint256"}],"name":"Birth","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"owner","type":"address"},{"indexed":false,"internalType":"uint256","name":"matronId","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"sireId","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"cooldownEndBlock","type":"uint256"}],"name":"Pregnant","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"from","type":"address"},{"indexed":false,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"Transfer","type":"event"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"constant":true,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"PetIndexToApproved","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"PetIndexToOwner","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"amountToAdulthood","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"amountToMiddleAge","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint256","name":"_tokenId","type":"uint256"}],"name":"approve","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_addr","type":"address"},{"internalType":"uint256","name":"_sireId","type":"uint256"}],"name":"approveSiring","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"autoBirthFee","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"count","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"_sireId","type":"uint256"},{"internalType":"uint256","name":"_matronId","type":"uint256"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"bidOnSiringAuction","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"_matronId","type":"uint256"},{"internalType":"uint256","name":"_sireId","type":"uint256"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"breedWithAuto","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"uint256","name":"_matronId","type":"uint256"},{"internalType":"uint256","name":"_sireId","type":"uint256"}],"name":"canBreedWith","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"cooldowns","outputs":[{"internalType":"uint32","name":"","type":"uint32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_owner","type":"address"},{"internalType":"uint256","name":"_genes","type":"uint256"}],"name":"createGen0Auction","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_owner","type":"address"}],"name":"createPet","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_owner","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"createPromoPet","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"_PetId","type":"uint256"},{"internalType":"uint256","name":"_startingPrice","type":"uint256"},{"internalType":"uint256","name":"_endingPrice","type":"uint256"},{"internalType":"uint256","name":"_duration","type":"uint256"}],"name":"createSaleAuction","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"_PetId","type":"uint256"},{"internalType":"uint256","name":"_startingPrice","type":"uint256"},{"internalType":"uint256","name":"_endingPrice","type":"uint256"},{"internalType":"uint256","name":"_duration","type":"uint256"}],"name":"createSiringAuction","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"dpetToken","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"_petId","type":"uint256"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"feedOnPet","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"gen0CreatedCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"gen0Price","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"geneScience","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getBalance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"uint256","name":"_id","type":"uint256"}],"name":"getPet","outputs":[{"internalType":"bool","name":"isGestating","type":"bool"},{"internalType":"bool","name":"isReady","type":"bool"},{"internalType":"uint256","name":"cooldownIndex","type":"uint256"},{"internalType":"uint256","name":"nextActionAt","type":"uint256"},{"internalType":"uint256","name":"siringWithId","type":"uint256"},{"internalType":"uint256","name":"birthTime","type":"uint256"},{"internalType":"uint256","name":"matronId","type":"uint256"},{"internalType":"uint256","name":"sireId","type":"uint256"},{"internalType":"uint256","name":"generation","type":"uint256"},{"internalType":"string","name":"genes","type":"string"},{"internalType":"uint256","name":"stages","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"_matronId","type":"uint256"}],"name":"giveBirth","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"uint256","name":"_PetId","type":"uint256"}],"name":"isPregnant","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"uint256","name":"_PetId","type":"uint256"}],"name":"isReadyToBreed","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"uint256","name":"_tokenId","type":"uint256"}],"name":"ownerOf","outputs":[{"internalType":"address","name":"owner","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"pause","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"paused","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"pregnantpets","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"saleAuction","outputs":[{"internalType":"contract SaleClockAuction","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"saleAuctionAddr","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"secondsPerBlock","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"_amountToAdulthood","type":"uint256"}],"name":"setAmountToAdulthood","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"_amountToMiddleAge","type":"uint256"}],"name":"setAmountToMiddleAge","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"val","type":"uint256"}],"name":"setAutoBirthFee","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_address","type":"address"}],"name":"setGeneScienceAddress","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_address","type":"address"}],"name":"setSaleAuctionAddress","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"secs","type":"uint256"}],"name":"setSecondsPerBlock","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_address","type":"address"}],"name":"setSiringAuctionAddress","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_stakingContract","type":"address"}],"name":"setStakingContract","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"sireAllowedToAddress","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"siringAuction","outputs":[{"internalType":"contract SiringClockAuction","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"siringAuctionAddr","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"stakingContract","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"bytes4","name":"_interfaceID","type":"bytes4"}],"name":"supportsInterface","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"_owner","type":"address"}],"name":"tokensOfOwner","outputs":[{"internalType":"uint256[]","name":"ownerTokens","type":"uint256[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint256","name":"_tokenId","type":"uint256"}],"name":"transfer","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_from","type":"address"},{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint256","name":"_tokenId","type":"uint256"}],"name":"transferFrom","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[],"name":"unpause","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"_gen0Price","type":"uint256"}],"name":"updateGen0Price","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[],"name":"withdrawBalance","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"}]')
    contract = web3.eth.contract(address=contract_address, abi=abi)
    
    x = contract.functions.tokensOfOwner(owner).call()
    #print(x)

    arr = []
    #for a in x:
        #pet = contract.functions.getPet(a).call()       
        #print('PET ID: ', a, ' stage: : ', pet[10], "\n")
        #if pet[10] == 1:
            #arr.append(a)
    return arr

def getDpetToken(web3):

    contract_address = '0xfb62AE373acA027177D1c18Ee0862817f9080d08'
    checkBalance = '0x2754D5c52ce12AeBe4f7e64911Dc2A73B2C1E51d'
    abi = json.loads('[{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[],"name":"Pause","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[],"name":"Unpause","type":"event"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"constant":true,"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"burn","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"subtractedValue","type":"uint256"}],"name":"decreaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"getBurnedAmountTotal","outputs":[{"internalType":"uint256","name":"_amount","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"addedValue","type":"uint256"}],"name":"increaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"isOwner","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"pause","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"paused","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"renounceOwnership","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_receiver","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_from","type":"address"},{"internalType":"address","name":"_receiver","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[],"name":"unpause","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]')
    contract = web3.eth.contract(address=contract_address, abi=abi)

    x = contract.functions.balanceOf(checkBalance).call()
    print(x)

    arr = []
    #for a in x:
        #pet = contract.functions.getPet(a).call()       
        #print('PET ID: ', a, ' stage: : ', pet[10], "\n")
        #if pet[10] == 1:
            #arr.append(a)
    return x    

def feed(x8abi, petidlist, owner, contract, privkey, web3):

    balance = web3.eth.get_balance(owner)
    print(web3.fromWei(balance, 'ether'))

    contract_address = contract

    abi = x8abi

    contract = web3.eth.contract(address=contract_address, abi=abi)

    send = 3
    amount = web3.toWei(send, 'ether')
    print(amount)
    
    nonce = web3.eth.getTransactionCount(owner)                
    token_tx = contract.functions.feedd2(petidlist, amount).buildTransaction({
        'chainId':56, 'gas': 1000000,'gasPrice': web3.toWei('6','gwei'), 'nonce':nonce
    })  
    sign_txn = web3.eth.account.signTransaction(token_tx, private_key=privkey)
    txnHash = web3.eth.sendRawTransaction(sign_txn.rawTransaction)   
    #done1 = binascii.hexlify(sign_txn).decode("utf-8")
    txnHashHex = txnHash.hex()
    print('txnHash.hex(): '+ txnHashHex)
    nonce += nonce;
    time.sleep(1)
    
def createPet(x8abi, loop, owner, revice, contract, privkey, web3):

    balance = web3.eth.get_balance(owner)
    print(web3.fromWei(balance, 'ether'))

    contract_address = contract

    abi = x8abi

    contract = web3.eth.contract(address=contract_address, abi=abi)

    send = 3
    amount = web3.toWei(send, 'ether')
    print(amount)

    nonce = web3.eth.getTransactionCount(owner)
    print(nonce)

    token_tx = contract.functions.grr5(revice, amount, loop).buildTransaction({
        'chainId':56, 'gas': 500000,'gasPrice': web3.toWei('6','gwei'), 'nonce':nonce
    })  
    sign_txn = web3.eth.account.signTransaction(token_tx, private_key=privkey)
    txnHash = web3.eth.sendRawTransaction(sign_txn.rawTransaction)   
    #done1 = binascii.hexlify(sign_txn).decode("utf-8")
    txnHashHex = txnHash.hex()
    print('txnHash.hex(): '+ txnHashHex)

def approvePet(x8abi, petCoreAddress, owner, contract, privkey, web3):

    contract_address = contract

    abi = x8abi

    contract = web3.eth.contract(address=contract_address, abi=abi)

    send = 10000
    amount = web3.toWei(send, 'ether')
    print(amount)

    nonce = web3.eth.getTransactionCount(owner)
    print(nonce)
    
    aprrove = petCoreAddress
    token_tx = contract.functions.grr1(aprrove, amount).buildTransaction({
        'chainId':56, 'gas': 200000,'gasPrice': web3.toWei('6','gwei'), 'nonce':nonce
    })  

    sign_txn = web3.eth.account.signTransaction(token_tx, private_key=privkey)
    txnHash = web3.eth.sendRawTransaction(sign_txn.rawTransaction)   
    #done1 = binascii.hexlify(sign_txn).decode("utf-8")
    txnHashHex = txnHash.hex()
    print('Approve Sucess! txnHash: '+ txnHashHex)

def withdraw(x8abi, tokenContract, owner, withdrawAmount, contract, privkey, web3):

    contract_address = contract

    abi = x8abi

    contract = web3.eth.contract(address=contract_address, abi=abi)

    send = withdrawAmount
    amount = web3.toWei(send, 'ether')
    print(amount)

    nonce = web3.eth.getTransactionCount(owner)
    print(nonce)
   
    token_tx = contract.functions.withdrawToken(tokenContract, amount).buildTransaction({
        'chainId':56, 'gas': 200000,'gasPrice': web3.toWei('6','gwei'), 'nonce':nonce
    })  

    sign_txn = web3.eth.account.signTransaction(token_tx, private_key=privkey)
    txnHash = web3.eth.sendRawTransaction(sign_txn.rawTransaction)   
    #done1 = binascii.hexlify(sign_txn).decode("utf-8")
    txnHashHex = txnHash.hex()
    print('Withdraw Sucess! txnHash: '+ txnHashHex)

def savePet(petidlist, address, token, sessionKey):

    url = "https://backend.mydefipet.com/apiv2/bsc/user/auth"
    url1 = "https://backend.mydefipet.com/apiv2/bsc/petreal"
    url2 = "https://backend.mydefipet.com/apiv2/bsc/savepet"

    headers = CaseInsensitiveDict()
    headers["accept"] = "*/*"
    headers["accept-encoding"] = "gzip, deflate, br"
    headers["accept-language"] = "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5"
    headers["authorization"] = "Basic dXNlcjpyZXN1QA=="
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://play.mydefipet.com"
    headers["referer"] = "https://play.mydefipet.com/"
    headers["sec-ch-ua"] = '" Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"'
    headers["sec-ch-ua-mobile"] = "?0"
    headers["sec-ch-ua-platform"] = '"Windows"'
    headers["sec-fetch-dest"] = "empty"
    headers["sec-fetch-mode"] = "cors"
    headers["sec-fetch-site"] = "same-site"
    headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36"

    data = f"wallet=bsc&address={address}&token={token}&clientVersion=1"
    arr3 = []
    arr5 = []

    for petid in petidlist:
        data1 = f"wallet=bsc&address={address}&token={token}&id={petid}&sessionKey={sessionKey}&clientVersion=1"
        data2 = f"wallet=bsc&address={address}&token={token}&petId={petid}&data=%7b%22cageID%22%3a%22%22%2c%22level%22%3a20%2c%22exp%22%3a0%2c%22inHotel%22%3afalse%2c%22IsBattle%22%3afalse%2c%22IsBattleSyncing%22%3afalse%2c%22Version%22%3a1%7d&clientVersion=1"
        
        #resp = requests.post(url, headers=headers, data=data)
        #print(resp.content)

        resp1 = requests.post(url1, headers=headers, data=data1)
        #json_data1 = json.loads(resp1.text)

        #json_data1_1 = json_data1["Pet"]
        #_id = json_data1["PetId"]
        #petData = json_data1["PetGameData"]
        #level = petData["level"]
       # if (level == 20 or level == '20'):
            #arr5.append(_id)
        
        #stage = json_data1_1["Stages"]
        
        #if stage == 1 or stage == '1':
            #arr3.append(_id)
            #print(f'Level{level}-------->PetId: {_id} Stages: {stage} \n')
        #else:
            #print(f'Level{level} 2-->PetId: {_id} Stages: {stage} \n')
        resp2 = requests.post(url2, headers=headers, data=data2)
        #json_data2 = json.loads(resp2.text)
       # i = json_data2["success"]
        print(resp1.text)
        print(resp2.text)
       # print(i)
    return arr3, arr5;

def buyToken(panabi, bep20, buyTokenAdd, address, privkey, web3, amount, mintoken, revice):
    #pancakeswap router
    #panRouterContractAddress = '0xD99D1c33F9fC3444f8101754aBC46c52416550D1' TEST
    panRouterContractAddress = '0x10ED43C718714eb63d5aA57B78B54704E256024E'

    #pancakeswap router abi     
    
    tokenAbi = bep20
    sender_address = address
    balance = web3.eth.get_balance(sender_address)
    #print(balance)
    
    humanReadable = web3.fromWei(balance,'ether')
    #print(humanReadable)
    
    #Contract Address of Token we want to buy
    tokenToBuy = web3.toChecksumAddress(buyTokenAdd)            #web3.toChecksumAddress("0x6615a63c260be84974166a5eddff223ce292cf3d")
    spend = web3.toChecksumAddress("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c")  #wbnb contract #wbnb0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd TEST
    
    #Setup the PancakeSwap contract
    contract = web3.eth.contract(address=panRouterContractAddress, abi=panabi)
    #decimals = contract.functions.decimals().call()
    #print(decimals)
    tokencontract = web3.eth.contract(address=tokenToBuy, abi=tokenAbi)
    decim =  tokencontract.functions.decimals().call()
    print(decim)
    nonce = web3.eth.get_transaction_count(sender_address)
    
    start = time.time()

    pancakeswap2_txn = contract.functions.swapExactETHForTokens(
    mintoken * 10 ** decim, # set to 0, or specify minimum amount of tokeny you want to receive - consider decimals!!!
    [spend,tokenToBuy],
    revice,
    (int(time.time()) + 10000)
    ).buildTransaction({
    'from': sender_address,
    'value': web3.toWei(amount,'ether'),#This is the Token(BNB) amount you want to Swap from
    'gas': 250000,
    'gasPrice': web3.toWei('6','gwei'),
    'nonce': nonce,
    })
    sendTrans = 0
    while sendTrans == 0:
        try:
            print('Let\'s go')

            print('Gas es: ', web3.eth.estimateGas(pancakeswap2_txn))

            print('-----Send-----')
            sign_txn = web3.eth.account.signTransaction(pancakeswap2_txn, private_key=privkey)

            txnHash = web3.eth.sendRawTransaction(sign_txn.rawTransaction)
            txnHashHex = txnHash.hex()

            receipt = web3.eth.waitForTransactionReceipt(web3.toHex(txnHash), timeout=600)
            print(f'Transaction has been done' )
            status = receipt['status']
            print(f'---->TxHash: {txnHashHex} - Status: {status}')
            if status == 0 or status == '0':
                print('--->Fail!')
            if status == 1 or status == '1':
                print('--->Success!')
                sendTrans = sendTrans + 1 
            print(f"https://bscscan.com/tx/{txnHashHex}")
        except Exception as e:
            print(e)    
    print("\n\n")
    
    #print(f"https://testnet.bscscan.com/tx/{web3.toHex(tx_token)}")

def sellPet(sellAbi, tokenID, sellPrice, privkey, web3):
    #pancakeswap router
    #panRouterContractAddress = '0xD99D1c33F9fC3444f8101754aBC46c52416550D1' TEST
    panRouterContractAddress = '0x10ED43C718714eb63d5aA57B78B54704E256024E'
    _smcAddress = '0xea2e87ff1bc1E52b640452694E2F143F7f8D64bE'
    _ERC20Token = '0x0000000000000000000000000000000000000000'
    sellContract = Web3.toChecksumAddress('0x92729ec47f292251a597c36883250996c10a35ba')
    
    price = web3.toWei(sellPrice,'ether')
    sender_address = Web3.toChecksumAddress('0x67c4109e6e2AA408c38De5b738867980784fc0df')
    
    balance = web3.eth.get_balance(sender_address)
    sellContract = web3.eth.contract(address=sellContract, abi=sellAbi)

    nonce = web3.eth.get_transaction_count(sender_address)
    token_tx = sellContract.functions.createSale(_smcAddress,tokenID,price,_ERC20Token).buildTransaction({
        'chainId':56, 'gas': 1000000,'gasPrice': web3.toWei('6','gwei'), 'nonce':nonce
    })  
    sign_txn = web3.eth.account.signTransaction(token_tx, private_key=privkey)
    txnHash = web3.eth.sendRawTransaction(sign_txn.rawTransaction)   
    txnHashHex = txnHash.hex()
    print('Sell Sucess! txnHash: '+ txnHashHex)

def approveSell(address, petCoreABI, petCore, tokenID, privkey, web3):
    sellAddress = '0x92729ec47f292251A597c36883250996c10a35ba'
    contract = web3.eth.contract(address=petCore, abi=petCoreABI)

    nonce = web3.eth.get_transaction_count(address)
    token_tx = contract.functions.approve(sellAddress,tokenID).buildTransaction({
        'chainId':56, 'gas': 500000,'gasPrice': web3.toWei('6','gwei'), 'nonce':nonce
    })  
    sign_txn = web3.eth.account.signTransaction(token_tx, private_key=privkey)
    txnHash = web3.eth.sendRawTransaction(sign_txn.rawTransaction)   
    txnHashHex = txnHash.hex()
    print('Aprrove PET Sucess! txnHash: '+ txnHashHex)

def main():
    #bsc = "https://data-seed-prebsc-1-s1.binance.org:8545/"
    bsc = "https://bsc-dataseed.binance.org/"
    web3 = Web3(Web3.HTTPProvider(bsc))
    print(web3.isConnected())

    #seed = os.getenv('seed')
    #privkey, address = seedToKey(seed)

    privkey = '4678d2d80404bc6f14b677700d3dcd25ccbe32909e8f23c2fba03b70f7eedbaa'
    address = '0xE5a8194B69f31Cb638c10903C4c70Fe51c124b67'
    #print(f'Private key: {privkey}')
    #print(f'Address: {address}')

    #contract = '0x2754D5c52ce12AeBe4f7e64911Dc2A73B2C1E51d' #Contract X8
    #revice = '0x67c4109e6e2AA408c38De5b738867980784fc0df'

    #dpettoken = '0xfb62ae373aca027177d1c18ee0862817f9080d08'
    #petCoreAddress = '0xea2e87ff1bc1E52b640452694E2F143F7f8D64bE'

    #token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZGRyZXNzIjoiMHg2N2M0MTA5ZTZlMkFBNDA4YzM4RGU1YjczODg2Nzk4MDc4NGZjMGRmIiwiZXhwaXJlVGltZSI6MTY0OTk1MjAzMCwiaXNzdWVUaW1lIjoxNjQ5NjkyODMwLCJtc2ciOiJiYTAxMyIsIndhbGxldCI6ImJzYyJ9.CPUQBwIKZm-LGhnOkLn3uniXOdpq_NLwMc8VQRQLy3E'
    #sessionkey = 'YnNjOjB4NjdjNDEwOWU2ZTJBQTQwOGMzOERlNWI3Mzg4Njc5ODA3ODRmYzBkZjox'
    
    #100000000000000000000000000
    #3000000000000000000
    #contents = json.dumps(sellAbi)
    ##jsonFile = open("sellAbi.json", "w")
    #jsonFile.write(contents)
    #jsonFile.close()

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


    #withdrawAmount = 6754
    #withdraw(x8abi, dpettoken, address, withdrawAmount, contract, privkey, web3)
    #99966774.99999

    #buy(panabi, bep20, dpettoken, web3, privkey)

    buyaddress = '0xfb62ae373aca027177d1c18ee0862817f9080d08'
    buyamount = 0.01
    minbuy = 11

    buyToken(panabi, bep20, buyaddress, address, privkey, web3, buyamount, minbuy, address)
    #approvePet(x8abi, petCoreAddress, address, contract, privkey, web3)

    balanceCheck = web3.eth.get_balance(address)
    humanReadable = web3.fromWei(balanceCheck,'ether')
    print(f'{address} :  {humanReadable} BNB')

    amount = 0.01
    #pinksale(amount, address, privkey, web3)
    #web3.eth.abi.encodeFunctionSignature('test');
    
def pinksale(amount, address, privkey, web3):
    abi = '[ { "inputs": [], "name": "contribute", "outputs": [], "stateMutability": "payable", "type": "function" } ]'    
    
    #contract_address =  #be sure to use a BSC Address in uppercase format like this 0x9F0818B... 
    contract_address = web3.toChecksumAddress('0xeed76cd72e22c430f7723d5a655218a8425989f3')
    abi = json.loads('[ { "inputs": [], "name": "claim", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [], "name": "contribute", "outputs": [], "stateMutability": "payable", "type": "function" }, { "inputs": [], "name": "finalize", "outputs": [], "stateMutability": "nonpayable", "type": "function" } ]')

    contract = web3.eth.contract(address=contract_address, abi=abi)

    nonce = web3.eth.getTransactionCount(address)

    #tx = contract.functions.contribute().buildTransaction({
    #    'chainId':56, 'value': web3.toWei(amount,'ether'), 'gas': 210000,'gasPrice': web3.toWei('6','gwei'), 'nonce':nonce
    #})
    tx = contract.functions.claim().buildTransaction({
        'chainId':56, 'gas': 210000,'gasPrice': web3.toWei('6','gwei'), 'nonce':nonce
    })

    sendTrans = 0
    while sendTrans == 0:
        try:
            print('Let\'s go')
            web3.eth.estimateGas(tx)
            print('-----Send-----')
            sign_txn = web3.eth.account.signTransaction(tx, private_key=privkey)
            txnHash = web3.eth.sendRawTransaction(sign_txn.rawTransaction)
            txnHashHex = txnHash.hex()

            receipt = web3.eth.waitForTransactionReceipt(web3.toHex(txnHash), timeout=600)
            print(f'Transaction has been done' )
            status = receipt['status']
            print(f'---->TxHash: {txnHashHex} - Status: {status}')
            if status == 0 or status == '0':
                print('--->Fail!')
            if status == 1 or status == '1':
                print('--->Success!')
                sendTrans = sendTrans + 1 
            print(f"https://bscscan.com/tx/{txnHashHex}")
        except Exception as e:
            print(e)    
    print("\n\n")

def buy(panabi, bep20, dpettoken, web3, privkey, buyAmount):
    buyaddress = '0xfb62ae373aca027177d1c18ee0862817f9080d08'
    revice = '0x2754D5c52ce12AeBe4f7e64911Dc2A73B2C1E51d'
    buyamount = buyAmount
    minbuy = 0    
    buyToken(panabi, bep20, dpettoken, privkey, web3, buyamount, minbuy, revice)

def sell(sellAbi, tokenID, sellPrice, address, petCoreABI, petCoreAddress, privkey, web3):  
    try:
        time.sleep(20)
        approveSell(address, petCoreABI, petCoreAddress, tokenID, privkey, web3)
        time.sleep(40)
        sellPet(sellAbi, tokenID, sellPrice, privkey, web3)
    except:
        print("An exception occurred")


main()










