import requests
import sqlite3
import random
import base64
import time
import xml.sax
from urllib.parse import urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

global conn, cursor

#Different Auth Credict
burp0_cookies = {}
unauth_burp0_headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:73.0) Gecko/20100101 Firefox/73.0', 'Accept': 'text/xml', 'Accept-Language': 'en-US,en;q=0.5', 'Accept-Encoding': 'gzip, deflate', 'Content-Type': 'text/xml', 'SOAPACTION': '"http://purenetworks.com/HNAP1/GetUSBStorageDevice"',  'Referer': 'http://192.168.0.1/Home.html', 'Connection': 'keep-alive'}

burp0_headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:73.0) Gecko/20100101 Firefox/73.0', 'Accept': 'text/xml', 'Accept-Language': 'en-US,en;q=0.5', 'Accept-Encoding': 'gzip, deflate', 'Content-Type': 'text/xml', 'SOAPACTION': '"http://purenetworks.com/HNAP1/GetUSBStorageDevice"', 'HNAP_AUTH': '6A72F54340697906484EC11B9551AFE5 1627483371', 'Referer': 'http://192.168.0.1/Home.html', 'Connection': 'keep-alive', 'Cookie': 'uid=h2NOOy61c'}

def dbInit():
    cursor.execute("DROP TABLE if exists unauth")
    cursor.execute(
        '''CREATE TABLE unauth (id INTEGER PRIMARY KEY AUTOINCREMENT, url VARCHAR(200) NOT NULL UNIQUE, statusCode VARCHAR(10) NOT NULL , content VARCHAR(200) NOT NULL );''')
    cursor.execute("DROP TABLE if exists auth")
    cursor.execute(
        '''CREATE TABLE auth (id INTEGER PRIMARY KEY AUTOINCREMENT, url VARCHAR(200) NOT NULL UNIQUE, statusCode VARCHAR(10) NOT NULL , content VARCHAR(200) NOT NULL );''')
    cursor.execute("DROP TABLE if exists potential")
    cursor.execute(
        '''CREATE TABLE potential (id INTEGER PRIMARY KEY AUTOINCREMENT, url VARCHAR(200) NOT NULL UNIQUE, statusCode VARCHAR(10) NOT NULL , content VARCHAR(200) NOT NULL );''')
    conn.commit()


def R(message):
    return "\033[1;91m{}\033[0;m".format(message)

def Y(message):
    return "\033[1;93m{}\033[0;m".format(message)

def reqUrl(url, verbose=False):
    try:
        if verbose:
            print("[*]Requesting {}".format(url))

        #Unauth requests
        r1 = requests.get(url, headers = burp0_headers, timeout = 3, verify = False, allow_redirects = False)
        resp1 = r1.content
        status1 = r1.status_code
        cursor.execute(
            "insert into unauth(url, statusCode, content) values ('{}', '{}', '{}')".format(url, status1, base64.b64encode(resp1).decode()))
        conn.commit()

        #Auth requests
        r2 = requests.get(url, headers = burp0_headers, timeout = 3, verify = False, allow_redirects = False, cookies = burp0_cookies)
        resp2 = r2.content
        status2 = r2.status_code
        cursor.execute(
            "insert into auth(url, statusCode, content) values ('{}', '{}', '{}')".format(url, status2, base64.b64encode(resp2).decode()))
        conn.commit()

        #Response Check
        if (status1 == status2 and resp1 == resp2):
            cursor.execute(
                "insert into potential(url, statusCode, content) values ('{}', '{}', '{}')".format(url, status2, base64.b64encode(resp2).decode()))
            conn.commit()
            print("[+]Potential UAI: {}".format(url))

        return True
    except KeyboardInterrupt:
        exit()
    except Exception as e:
        # print(e)
        err = e.__class__.__name__
        print("[-]Error in {} as {}".format(url, err))
        return False


def list2file(list, filename):
    with open(filename, "w") as f:
        for i in range(len(list)):
            if i == len(list)-1:
                f.write("{}".format(list[i]))
            else:
                f.write("{}\n".format(list[i]))

def text2requests(text):
    headers = {}
    for t in text.split("\n"):
        key, value = t.split(": ")
        headers[key] = value
    print(headers)

if __name__ == "__main__":
    vms = ['Amcrest  IP2M841',
           'ASUS     AC55U',
           'D-Link   DIR-868L',
           'D-Link   DIR-412',
           'D-Link   DIR-816',
           'D-Link   DAP-1320',
           'H3C      MAGIC',
           'Mercury  MIPC372-4',
           'Mercury  MNVR408',
           'Nettcore  G1',
           'Netgear  PLW1000',
           'Netgear  W104',
           'Netgear  WNDR4000',
           'Qihoo360 F5C',
           'Tenda    G103',
           'TP-Link  GP110',
           'Wavlink  AC1200']
    urlDic = {"IP2M841": "http://192.168.1.61",#admin	password123
              "AC55U": "http://192.168.1.60", #admin	admin12345
              "MAGIC": "http://192.168.1.41", #12345aaaaa
              "MIPC372-4": "http://192.168.1.63", #admin admin
              "MNVR408": "http://192.168.1.71", #admin	aaaaaaaa
              "G1": "http://192.168.1.1", #admin12345
              "PLW1000": "http://192.168.1.23", #admin	password
              "W104": "http://192.168.1.53", #admin	password
              "WNDR4000": "http://192.168.1.1", #admin password
              "F5C": "http://192.168.0.1",
              "G103": "http://192.168.1.11", #root	admin
              "GP110": "http://192.168.1.13", #aaaaa12345
              "AC1200": "http://192.168.1.40", #admin12345
              "DIR-816": "http://192.168.0.1", #admin 123456
              "DIR-868L": "http://192.168.0.1",  # admin 123456
              "DAP-1320": "http://192.168.0.50"
              }
    # vms = ['D-Link   DIR-868L']

    #You need to change this Boolean Variable
    firmadyne = True
    for vm in vms:
        vendor, model = vm.split()
        print("[*]Checking {} {}".format(vendor, model))
        if firmadyne:
            conn = sqlite3.connect('dbs/{}_{}_firmadyne.db3'.format(vendor, model))
        else:
            conn = sqlite3.connect('dbs/{}_{}.db3'.format(vendor, model))
        cursor = conn.cursor()

        time_start = time.time()
        dbInit()

        if firmadyne:
            paths = open("FirmadynePaths/{}_{}.txt".format(vendor, model))
        else:
            paths = open("{}/{}/{}_{}.txt".format(vendor, model, vendor, model)).readlines()
        number = 0
        for path in paths:
            url = urljoin(urlDic[model], path)
            reqUrl(url.strip())
            # time.sleep(1)

        sNumber = cursor.execute("select count(*) from potential")
        sLen = sNumber.fetchone()
        print("[*]Checking {} {} Over".format(vendor, model))
        print("[*]The number of url maybe UAI: {}".format(sLen[0]))
        print("[*]Time cost: {:.2f}s".format(time.time() - time_start))
        conn.close()

        log = open("log.txt", "a")
        log.write("[*]{} {} The number of url maybe UAI: {}\n".format(vendor, model, sLen[0]))
        log.write("[*]{} {} Time cost: {:.2f}s".format(vendor, model, time.time() - time_start))
        log.close()
