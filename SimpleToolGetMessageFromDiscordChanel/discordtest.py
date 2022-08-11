from re import A
from wsgiref import headers
from regex import X
import requests
import json
import re
  
def Find(string):
    # findall() has been used 
    # with valid conditions for urls in string
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex,string)      
    return [x[0] for x in url];
      

def test(channelid):
        headers = {
            'authorization': 'NDI4NDQzNzA0NzM1NTYzNzc4.YalxWw.iKNL5cWStRAzJ91H8Zp6m-M0VJ0'
        }
        r = requests.get(
            f'https://discord.com/api/v9/channels/{channelid}/messages', headers=headers)
        jsonn = json.loads(r.text)    

        for idx, x in enumerate(jsonn):   
            print(idx, x, '\n')
            # Driver Code
            object_strng = str(x)
            string = object_strng
            print("Urls: ", Find(string))
            if idx == 3:
                break;
        
test('758323596694257684')
