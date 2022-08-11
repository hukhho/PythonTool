from web3 import Web3
import time

w3 = Web3()

# Open a file with access mode 'a'
file_object = open('walletDead.txt', 'a')
seconds = time.time()
time1 = time.ctime(seconds)
time1 = '\n' + time1
file_object.write(time1)

count = 0
while count == 0:
   acct = w3.eth.account.create()
   if acct.address.endswith("c0ca"):
      print(f"public address: {acct.address}")
      print(f"private key: {acct.key.hex()}")
      str1 = "\npublic address: " +  acct.address + " |  priv: " + acct.key.hex()
    
      file_object.write(str1)

      count += 1

file_object.close()

otp = 0000
phone = 84362316265
data = '{"password":"' + otp + '","login":"' + phone + '"}'
print(data)