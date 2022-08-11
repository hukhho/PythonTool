from usp.tree import sitemap_tree_for_homepage
import requests
import re
from six.moves import urllib
from bs4 import BeautifulSoup
# importing all required libraries
import telebot
from telethon.sync import TelegramClient
from telethon.tl.types import InputPeerUser, InputPeerChannel
from telethon import TelegramClient, sync, events

def sendMess(mess):


    # get your api_id, api_hash, token
    # from telegram as described above
    api_id = '15082692'
    api_hash = '88777bcf8dfbf84eb92a489705ba50e0'
    token = '5105504322:AAFQcMh566omAUI0KFmW1YHZ776796N2VVs'
    message = mess

    # your phone number
    phone = '+84392725127'

    # creating a telegram session and assigning
    # it to a variable client
    client = TelegramClient('session', api_id, api_hash)

    # connecting and building the session
    client.connect()

    # in case of script ran first time it will
    # ask either to input token or otp sent to
    # number or sent or your telegram id
    if not client.is_user_authorized():
        
            client.send_code_request(phone)
            
            # signing in the client
            client.sign_in(phone, input('Enter the code: '))


    try:
            # receiver user_id and access_hash, use
            # my user_id and access_hash for reference
            receiver = InputPeerUser(2106680655, 0)
          
            
            # sending message using telegram client
            client.send_message(receiver, message, parse_mode='html')

      
            print('ok')
    except Exception as e:
            
            # there may be many error coming in while like peer
            # error, wrong access_hash, flood_error, etc
            print(e);

    # disconnecting the telegram session
    client.disconnect()


def main():
    tree = sitemap_tree_for_homepage('https://blog.alphaventuredao.io/sitemap-posts.xml')

    # all_pages() returns an Iterator
    
    link1= "https://blog.alphaventuredao.io/how-can-you-engage-in-alpha-venture-dao/"
    link2= "https://blog.alphaventuredao.io/alpha-finance-lab-rebrands-expands-into-alpha-venture-dao-to-disrupt-web3-ecosystem/"
    
    for index, page in enumerate(tree.all_pages(), start=0):
        if (0 < index < 10):
            if (page.url != link1 and page.url != link2):           
                link = page.url
                f = requests.get(link)
                
                txt = f.text
                
                soup = BeautifulSoup(txt)
                yy = soup.get_text()

                xnxx = re.findall("[\(](\w+)[,][ ][0-9][\)][\.]", yy, re.DOTALL)
                if len(xnxx) > 0:
                    print(index, page.url, page.last_modified)   
                    print(xnxx)
                    for mess in xnxx:
                        sendMess(mess);
            else:
                print("not thing");

                
while True:
  main()  


