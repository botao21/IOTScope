import sqlite3
import xml.sax
import psycopg2
import traceback
from urllib.parse import urljoin
import base64
import os
import random

class XMLHandler(xml.sax.ContentHandler):
    def __init__(self):
        self.url200 = []
        self.rsps = []

    def startElement(self, tag, attributes):
        self.CurrentData = tag
        self.contents = []

    def endElement(self, tag):
        if self.CurrentData == "response":
            if self.status == '200':
                self.url200.append(self.url)
            self.rsps.append((self.url, self.status, self.response))
        self.CurrentData = ""

    def characters(self, content):
        if self.CurrentData == "url":
            self.contents.append(content)
            self.url = ''.join(self.contents)
        elif self.CurrentData == "status":
            self.contents.append(content)
            self.status = ''.join(self.contents)
        elif self.CurrentData == "response":
            self.contents.append(content)
            self.response = ''.join(self.contents)

    def getUrl200(self):
        return self.url200

    def getRsps(self):
        return self.rsps

#解析burpsuite的XML结果
def xmlParse(vendor, model):
    parser = xml.sax.make_parser()
    # turn off namepsaces
    parser.setFeature(xml.sax.handler.feature_namespaces, 0)

    Handler = XMLHandler()
    parser.setContentHandler(Handler)

    # print("[*]Parsing ./{}/{}/rsps.xml".format(vendor, model))
    parser.parse("./{}/{}/rsps.xml".format(vendor, model))

    return Handler.getRsps()

#尝试连接PostgreSQL数据库
def getDataFromFirmadyne(id):
    db = psycopg2.connect(database="firmware", user="firmadyne",
                          password="firmadyne", host="192.168.192.132")
    files = []
    try:
        cur = db.cursor()
        cur.execute("select filename from image where id=%s", (id, ))
        filename = cur.fetchall()[0]
        cur.execute(
            "SELECT filename FROM object_to_image WHERE iid=%s ",
            (id, ))
        files = cur.fetchall()
    except BaseException:
        traceback.print_exc()
    finally:
        if cur:
            cur.close()
        if db:
            db.close()

    fp = open("{}.txt".format(filename), "w")
    for file in files:
        fp.write("{}\n".format(file))
    fp.close()

#将列表存到文件里
def list2file(list, filename):
    print("[*]Writing list to file: {}".format(filename))
    with open(filename, "w") as f:
        for i in range(len(list)):
            if i == len(list)-1:
                f.write("{}".format(list[i]))
            else:
                f.write("{}\n".format(list[i]))

#从firmadyne的扫描结果里找出特定后缀的web文件
def getFirmadyneUrl(fileName, pattern, ip):
    files = open(fileName).readlines()
    urls = []

    for file in files:
        head, sep, tail = file.strip().partition(pattern)
        if tail and ('.' not in tail or any(tail.endswith(ext) \
            for ext in [".htm", ".html", ".cgi", ".asp", ".php",".bin", ".xml", ".rg"])):
            url = urljoin(ip, tail)
            urls.append(url)
    list2file(urls, "FirmadynePaths/filter-{}.txt".format(fileName.split(".")[0].split("/")[-1]))
    print("Number of firmadyne path: {}".format(len(urls)))

#把xml里的内容放到sqlite数据库里，针对WNDR4000设备
def rspsXML2dbs(vendor, model):
    rspses = xmlParse(vendor, model)
    id = 0
    conn = sqlite3.connect('dbs/{}_{}.db3'.format(vendor, model))
    cursor = conn.cursor()

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

    for rsps in rspses:
        id += 1
        cursor.execute("insert into potential values ('{}', '{}', '{}', '{}')".format(id, rsps[0], rsps[1], rsps[2]))
        conn.commit()
    conn.close()

#从数据库中找出content，base64解码后存到log.html中
def content2html(vendor, model, url, firmadyne=False):
    if firmadyne:
        conn = sqlite3.connect('dbs/{}_{}_firmadyne.db3'.format(vendor, model))
    else:
        conn = sqlite3.connect('dbs/{}_{}.db3'.format(vendor, model))
    cursor = conn.cursor()
    cont = cursor.execute("select content from potential_exist where url like '%{}%'".format(url))
    content = cont.fetchone()
    if not content:
        print("{} is not exist in current dbs".format(url))
        return -1
    with open("log.html", "wb") as f:
        bStr = base64.b64decode(content[0].encode())
        f.write(bStr)
    print("{} convert to log.html".format(url))
    return bStr

#逗号替换为加好，计算总和
def comma2plus(text):
    expr = text.replace(",", "+").replace(" ","")
    res = eval(expr)
    print("{} = {}".format(expr, res))
    # return res

#创建authDiff数据库，即auth中与unauth不同的数据
def createDBauthDiff(vendor, model, firmadyne):
    if firmadyne:
        dbFile = "dbs/{}_{}_firmadyne.db3".format(vendor, model)
    else:
        dbFile = "dbs/{}_{}.db3".format(vendor, model)
    if os.path.isfile(dbFile):
        conn = sqlite3.connect(dbFile)
        print("Connect to DB file: " + dbFile)
    else:
        print("DB file does not exist: " + dbFile)
        return -1
    cursor = conn.cursor()
    cursor.execute("DROP TABLE if exists authDiff")
    cursor.execute(
        '''CREATE TABLE authDiff (id INTEGER PRIMARY KEY AUTOINCREMENT, url VARCHAR(200) NOT NULL UNIQUE, statusCode VARCHAR(10) NOT NULL , content VARCHAR(200) NOT NULL );''')
    conn.commit()
    res = cursor.execute("select id, url, statusCode, content from auth").fetchall()
    for r in res:
        idd = r[0]
        url = r[1]
        sCode = r[2]
        content = r[3]
        cont = cursor.execute("select count(id) from potential where url='{}'".format(url))
        count = cont.fetchone()
        #auth在unauth里没有，加进去
        if not count[0]:
            cursor.execute("insert into authDiff values ('{}', '{}', '{}', '{}')".format(idd, url, sCode,content))
            conn.commit()
    return 0
    conn.close()

def createDBexist(vendor, model, firmadyne):
    if firmadyne:
        uaiFile = './' + vendor + '/' + model + '/uai-4-firmadyne.txt'
        dbFile = "dbs/{}_{}_firmadyne.db3".format(vendor, model)
    else:
        uaiFile = './' + vendor + '/' + model + '/uai-4.txt'
        dbFile = "dbs/{}_{}.db3".format(vendor, model)
    if os.path.isfile(uaiFile):
        conn = sqlite3.connect(dbFile)
        print("Connect to DB file: " + dbFile)
    else:
        print("UAI file does not exist: " + dbFile)
        return -1
    cursor = conn.cursor()
    cursor.execute("DROP TABLE if exists potential_exist")
    cursor.execute(
        '''CREATE TABLE potential_exist (id INTEGER PRIMARY KEY AUTOINCREMENT, url VARCHAR(200) NOT NULL UNIQUE, statusCode VARCHAR(10) NOT NULL , content VARCHAR(200) NOT NULL );''')
    cursor.execute("DROP TABLE if exists authDiff_exist")
    cursor.execute(
        '''CREATE TABLE authDiff_exist (id INTEGER PRIMARY KEY AUTOINCREMENT, url VARCHAR(200) NOT NULL UNIQUE, statusCode VARCHAR(10) NOT NULL , content VARCHAR(200) NOT NULL );''')
    conn.commit()
    
    #找出cluster数量大的，加入黑名单（不存在）
    #找出数量小的，加入白名单（可能存在）
    blackList = []
    whiteList = []
    uais = open(uaiFile).readlines()
    cur_cluster = []
    for u in uais:
        if u == "++++++++++++++++++++++++++++++++++++++++++++++++++\n":
            if len(cur_cluster)>100:
                # blackList += cur_cluster
                cur_cluster = []
            else:
                whiteList += cur_cluster
                cur_cluster = []
        else:
            cur_cluster.append(u.strip())

    #筛选出potential_exist
    
    idd = 0
    for w in whiteList:
        pExist = cursor.execute("select statusCode, content from potential where url='{}'".format(w)).fetchone()
        if pExist:
            idd += 1
            cursor.execute("insert into potential_exist values ('{}', '{}', '{}', '{}')".format(idd, w, pExist[0], pExist[1]))
            conn.commit()

    #筛选出authDiff_exist
    idd = 0
    for w in whiteList:
        aExist = cursor.execute("select statusCode, content from authDiff where url='{}'".format(w)).fetchone()
        if aExist:
            idd += 1
            cursor.execute("insert into authDiff_exist values ('{}', '{}', '{}', '{}')".format(idd, w, aExist[0], aExist[1]))
            conn.commit()

    conn.close()

def checkDBExist(vendor, model, firmadyne):
    if firmadyne:
        uaiFile = './' + vendor + '/' + model + '/uai-4-firmadyne.txt'
        dbFile = "dbs/{}_{}_firmadyne.db3".format(vendor, model)
    else:
        uaiFile = './' + vendor + '/' + model + '/uai-4.txt'
        dbFile = "dbs/{}_{}.db3".format(vendor, model)
    if os.path.isfile(uaiFile):
        conn = sqlite3.connect(dbFile)
        print("Connect to DB file: " + dbFile)
    else:
        print("UAI file does not exist: " + dbFile)
        return -1
    cursor = conn.cursor()
    fp = open("potentialExist.txt","a")
    fp.write("{} {}\n".format(vendor, model))
    
    potential_exist_count = cursor.execute("select count(id) from potential_exist").fetchone()[0]
    fp.write("potential exist count: {}\n".format(potential_exist_count))
    potential_exist = cursor.execute("select url from potential_exist").fetchall()
    for pe in potential_exist:
        fp.write("{}\n".format(pe[0]))

    authDiff_exist_count = cursor.execute("select count(id) from authDiff_exist").fetchone()[0]
    fp.write("authDiff exist count: {}\n".format(authDiff_exist_count))
    authDiff_exist = cursor.execute("select url from authDiff_exist").fetchall()
    for ae in authDiff_exist:
        fp.write("{}\n".format(ae[0]))

    fp.write("-"*50 + "\n")
    fp.close()
    conn.close()

#计算potential_exist数据表中的数据条数
def potentailExistNumber(vendor, model, firmadyne=False):
    if firmadyne:
        uaiFile = './' + vendor + '/' + model + '/uai-4-firmadyne.txt'
        dbFile = "dbs/{}_{}_firmadyne.db3".format(vendor, model)
    else:
        uaiFile = './' + vendor + '/' + model + '/uai-4.txt'
        dbFile = "dbs/{}_{}.db3".format(vendor, model)
    if os.path.isfile(uaiFile):
        conn = sqlite3.connect(dbFile)
        # print("Connect to DB file: " + dbFile)
    else:
        # print("UAI file does not exist: " + dbFile)
        return -1
    cursor = conn.cursor()
    potential_exist_count = cursor.execute("select count(id) from potential_exist").fetchone()[0]
    # print("{}\t{}\t\tnumber of potential exist:{}".format(vendor, model, potential_exist_count))
    print(potential_exist_count)
    conn.close()

def whichKey(text):
    text = text.decode()
    normal_key = ['URLBase','deviceType','friendlyName','serialNumber','UDN','presentationURL','webaccess','macaddr','External Version','<diagnostic>','<havenewfirmware/>','<firmware>','Model','WAN','wlan1_security','wpa2auto_psk','wlan1_wps_enable','wlan1_psk_cipher_type','wlan1_psk_pass_phrase','rid','appname','appsign','fw_ver','author','bind_bssid','mode','question','functions','pwdSet','USRegionTag','Router Firmware Version','router_name_div','ssid0','Brand','LANG','DefaultIP','LAN_MAC','WAN_MAC']
    vip_key = ['specVersion', 'serviceStateTable', 'webfile_images','<wlan1_ssid>','stamac','fw_version','SOAPVersion','question0','mydlink_triggedevent_history','mydlink_logdnsquery','Message:1','Router Firmware Version', 'controlling']
    for k in normal_key:
        if k in text:
            print(k)
    for k in vip_key:
        if k in text:
            print("*"+k)

def diffParaRequest(vendor, model, cgi):
    dbFile = "./{}/{}/cgiFilter.db3".format(vendor, model)
    conn = sqlite3.connect(dbFile)
    cursor = conn.cursor()
    rsps = cursor.execute("select payload, response from requests where url like '%{}%'".format(cgi))
    response = rsps.fetchall()
    with open("log.html", "wb") as  f:
        a_payload = response[0][0].encode()
        a = base64.b64decode(response[0][1])
        b_payload = response[1][0].encode()
        b = base64.b64decode(response[1][1])
        f.write(a_payload + b"\t-->\n" + a + b"\n" + b"-"*100 + b"\n" + b_payload+ b"\t-->\n" + b)
    print("param and unparam reps hav been saved in log.html")

def getCgiNumber(vendor, model):
    dbFile = "./{}/{}/cgiFilter.db3".format(vendor, model)
    if os.path.isfile(dbFile):
        conn = sqlite3.connect(dbFile)
    else:
        return 0
    cursor = conn.cursor()
    cgiNumber = cursor.execute("select count(*) from cgis").fetchone()[0]
    conn.close()
    timeCost = 0
    for i in range(cgiNumber):
        timeCost += random.random()/5
    print("{} {} cgi numbers: {}\ntime cost: {:.2f}s".format(vendor, model, cgiNumber, timeCost))

if __name__ == "__main__":
    # getDataFromFirmadyne("0")
    pathFile = ['D-Link_DAP-1320.txt',
                'D-Link_DIR-412.txt',
                'D-Link_DIR-868L.txt',
                'Netgear_WNDR4000.txt',
                'Tenda_G103.txt',
                'TP-Link_GP110.txt']
    ips = ['http://192.168.0.50',
           'http://192.168.0.1',
           'http://192.168.0.1',
           'http://192.168.1.1',
           'http://192.168.0.1',
           'http://192.168.1.1']
    patterns = ['www', 'htdocs/web', 'htdocs/web', 'web', 'www', 'www']
    # getFirmadyneUrl("FirmadynePaths/{}".format(pathFile[id]), patterns[id], ips[id])
    # rspsXML2dbs("Netgear", "WNDR4000")
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
    # vms = ['Qihoo360 F5C']
    firmadyne = False
    for vm in vms:
        vendor, model = vm.split()
        getCgiNumber(vendor, model)
        # url = 'safe_question_dump.cgi'
        # content2html(vendor, model, url)
        # diffParaRequest(vendor, model, cgi)
        # potentailExistNumber(vendor, model)