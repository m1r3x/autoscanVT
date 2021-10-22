import requests
import os
import fitz
import re

api_keys = [] #add your own keys(comma separated strings, recommended at least 2 keys)

key_count = 0   #don't change this

blacklist = ["exe","doc","docx","zip","xml","zip","apk","pdf","txt","php","js","db","sql","png","dex","jpg","smali","sqlite","properties","ttf","core","action","sdk","webp","otf","version","dtd","text","style"]

digits = "0123456789"

malicious_list = []
clean_list = []

ip_url = "http://www.virustotal.com/api/v3/ip_addresses/"
dom_url = "http://www.virustotal.com/api/v3/domains/"

address_list = []

pattern_ip = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
pattern_domain = re.compile(r'(([a-z]{1,}\.)+[a-z]{1,})')


if len(api_keys) == 0:
    print("No VirusTotal api keys added. Please go to the script and add your keys.")
    exit()

text_file = input("Drag and drop the file here(txt or pdf): ").strip("'")

x = text_file.rfind(".")

if text_file[x+1:] == "txt":
    with open(text_file, 'r') as file:
        text = file.read()

elif text_file[x+1:] == "pdf":
    with fitz.open(text_file) as doc:
        text = ""
        for page in doc:
            text += page.getText()

 
for line in text.split("\n"):
    try:
        x = pattern_ip.search(line)[0]
        address_list.append(x)
    except:
        pass

    try:
        y = pattern_domain.search(line)[0]
        if y.split(".")[-1] not in blacklist and len(y.split(".")[-1]) > 1:
            address_list.append(y)
    except:
        pass

address_list = sorted(list(set(address_list)))

print()
print("Scanning these addresses:",(", ").join(address_list))
print()

def get_key(list):
    global key_count
    key_count += 1
    index = key_count%len(list)
    return list[index]

def get_header():
    header = {}
    header['x-apikey'] = get_key(api_keys)
    return header

def scan(x):
    z = i.split(".")
    if len(z) == 4 and z[-1][0] in digits:
        url = ip_url+i
    else:
        url = dom_url+i

    req = requests.get(url, headers = get_header())
    req2 = requests.get(url+"/communicating_files", headers = get_header())
    votes = requests.get(url+"/votes", headers = get_header()).json()

    if ('"result": "malicious"' in req.text or '"category": "malicious"' in req2.text) and int(votes["meta"]["count"]) < 50:
        malicious_list.append(i)
    else:
        clean_list.append(i)

for i in address_list:
    scan(i)

print("Malicious addresses:")
for i in malicious_list:
    print(i)

print()

print("Clean(or non existent) addresses:")
for i in clean_list:
    print(i)

print()