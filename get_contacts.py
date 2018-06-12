#!/usr/bin/env python
import sys
import time
import requests
import hashlib
import re
import string
import json
import pandas as pd
from bs4 import BeautifulSoup
from pprint import pprint

init_csrf = "nulltoken"

def get_json_value(data, id):
    for item in data:
        if item["varid"] == id:
            return item["varvalue"]
    return None

def get_challenge(target_ip):
    # get the challenge to authenticate against the SpeedportEntry2
    time_ms = round(time.time() * 1000)

    r = requests.get(
        'http://{host}/data/Login.json?_time={time}&_rand=666&csrf_token={csrf}'
        .format(host=target_ip, time=time_ms, csrf=init_csrf))

    data = r.json()

    challenge = get_json_value(data, "challenge")
    if challenge != None:
        return challenge

    # On newer Firmware the challenge is embedded in the html page
    r = requests.get('http://{host}/html/login/index.html'.format(host=target_ip))
    # I guess we can safely assume that there will be only one challenge in the index.html
    challenge = re.findall(r'challenge = \"([A-Za-z0-9]+)\"', r.text)[0]
    if challenge != None:
        return challenge

    return None


def gen_passwd(password, challenge):
    # Create a sha256 sum of the password+challenge
    return hashlib.sha256(challenge.encode() + ":".encode() + password.encode()).hexdigest()

def get_file(cookie_jar, path):
    return requests.get("http://{host}/{path}".format(host=sys.argv[1], path=path), cookies=cookie_jar)

def login(target_ip, hashed_pw, challenge):
    # Send a post request to the Login.json which contains the hashed_pw
    # and the static csrf token
    r = requests.post("http://{}/data/Login.json".format(target_ip),
                      data={
                        'password': hashed_pw,
                        'showpw': 0,
                        'csrf_token': init_csrf,
                        'challengev': challenge})
    cookies = r.cookies
    r = get_file(cookies, "data/Login.json")
    if get_json_value(r.json(), "login") != "true":
        print("login failed")
        return None
    return cookies



def parse_contacts(contacts_json):
    contacts = pd.DataFrame(columns=["firstname", "lastname", "personal", "mobile", "work"])
    for item in contacts_json.json():
        if item["varid"] == "addbookentry":
            contacts.loc[len(contacts)] = [
                get_json_value(item["varvalue"], "phonebook_vorname"),
                get_json_value(item["varvalue"], "phonebook_name"),
                get_json_value(item["varvalue"], "phonebook_number_p"),
                get_json_value(item["varvalue"], "phonebook_number_m"),
                get_json_value(item["varvalue"], "phonebook_number_a")
            ]
    return contacts

challenge = get_challenge(sys.argv[1])
hashpw = gen_passwd(sys.argv[2], challenge)
cookie_jar = login(sys.argv[1], hashpw, challenge)

frame = parse_contacts(get_file(cookie_jar, "data/DECTStation.json"))
print(frame.to_csv(index=False))