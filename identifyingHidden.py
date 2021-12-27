#对存在的URL返回结果进行过滤
import re
import time
import xml.sax
import nltk
import sqlite3
import collections
import os
import base64
import requests
from lxml import etree
from urllib.parse import urljoin
from dbAssistant import list2file

#input:vendor，model
#output:可能存在信息泄露的URL返回包
def filterInfoLeak(vendor, model, firmadyne):
    normal_key = ['URLBase','deviceType','friendlyName','serialNumber','UDN','presentationURL','webaccess','<firmware>','Model','WAN','wlan1_security','wpa2auto_psk','wlan1_wps_enable','wlan1_psk_cipher_type','wlan1_psk_pass_phrase','rid','appname','appsign','fw_ver','author','mode','question','pwdSet','USRegionTag','router_name_div','ssid0','Brand','LANG','DefaultIP','LAN_MAC','WAN_MAC','specVersion', 'serviceStateTable', 'webfile_images','<wlan1_ssid>','stamac','fw_version','SOAPVersion','question0','mydlink_triggedevent_history','mydlink_logdnsquery','Message:1','Router Firmware Version','controlling','macaddr','External Version','<diagnostic>','<havenewfirmware/>','bind_bssid','functions','Recovered']
    if firmadyne:
        dbFile = "dbs/{}_{}_firmadyne.db3".format(vendor, model)
    else:
        dbFile = "dbs/{}_{}.db3".format(vendor, model)
    if os.path.isfile(dbFile):
        conn = sqlite3.connect(dbFile)
        # print("Connect to DB file: " + dbFile)
    else:
        return -1
    cursor = conn.cursor()
    conts = cursor.execute("select url, content from potential_exist").fetchall()
    outFile = "infoLeakPages.csv"
    fp = open(outFile, "a")
    fp.write("{},{}\nrank,url,keys\n".format(vendor, model))
    num = 0
    for cont in conts:
        url = cont[0]
        rank = 0
        bStr = base64.b64decode(cont[1].encode()).decode("utf-8","ignore")
        keys = []
        for key in normal_key:
            if key in bStr:
                rank += 1
                keys.append(key)

        if rank > 2:
            fp.write("{},{},{}\n".format(rank, url, keys))
            num += 1
    fp.write("Filtered Number: {}\n".format(num))
    fp.write("-"*150 + "\n")
    fp.close()

def get_file_path(root_path, file_list):
    #获取该目录下所有的文件名称和目录名称
    dir_or_files = os.listdir(root_path)
    for dir_file in dir_or_files:
        #获取目录或者文件的路径
        dir_file_path = os.path.join(root_path,dir_file)
        #判断该路径为文件还是路径
        if os.path.isdir(dir_file_path):
            #递归获取所有文件和目录的路径
            get_file_path(dir_file_path, file_list)
        elif dir_file_path.endswith(".html") or dir_file_path.endswith(".js") \
                or dir_file_path.endswith(".htm") or dir_file_path.endswith(".php"):
            file_list.append(dir_file_path)

def mkTables(cursor, conn):
    cursor.execute("drop table if exists cgis")
    cursor.execute("create table cgis (ID integer primary key, cgi varchar(100) not null)")
    cursor.execute("drop table if exists params")
    cursor.execute("create table params (ID integer primary key, cgiID integer, name varchar(100) not null, " +
                   "defaultValue varchar(100), type varchar(100), class varchar(100)," +
                   "maxlength varchar(100))")
    cursor.execute("drop table if exists requests")
    cursor.execute(
        "create table requests (ID integer primary key, url varchar(200), payload varchar(500), response varchar(1000), diff varchar(10))")
    conn.commit()

def ajaxCgiParams(vendor, model):
    rules = ["\$\.post\(([^,]+,[^\)]+),\s*function\s*\(data\)\s*\{",
             # "$.post( path +\"auth_info_failure.cgi\",{\"mac\":macStr},showMessage);",
             'srouter.init.common.ajax\(([^,]+,[^\)]+),\s*function\s*\(data\)\s*\{',
             # '$.post("/app/webauth_example/webs/auth_info_check.cgi",obj,function(data){',
             'ajaxObj\.sendRequest\(([^,]+,[^;]+)\);'
             ]
    firmPath = ".\\{}\\{}\\firmware".format(vendor, model)
    file_list = []
    get_file_path(firmPath, file_list)

    #get cgis
    conn = sqlite3.connect('dbs/{}_{}.db3'.format(vendor, model))
    cursor = conn.cursor()
    urlcur = cursor.execute("select url from potential_exist")
    urls = urlcur.fetchall()
    cgis = set([])
    for u in urls:
        url = u[0]
        if url.endswith(".cgi") or url.endswith(".php"):
            cgis.add(u[0].split("/")[-1])
    conn.close()

    #matching rules
    keywords = set()
    resList = []
    for f in file_list:
        for cgi in cgis:
            try:
                cont = open(f, encoding='gbk', errors='ignore').read()
            except:
                cont = ""
            if cont and cgi in cont:
                for rule in rules:
                    res = re.findall(rule, cont)
                    for r in res:
                        pRes = re.sub("[^(\x21-\x7e)]","",r)
                        cgi = pRes[:pRes.index(",")]
                        params = pRes[pRes.index(",")+1:]
                        if re.match("[\w\.]+", params): #参数是一个变量，去上下文中寻找
                            typ, postParams = extractCgiParams(params, cont)
                            if typ == "dict":
                                for k in postParams.keys():
                                    keywords.add(k)
                            elif typ == "list":
                                for k in postParams:
                                    keywords.add(k)
                        else:#参数是字典格式的
                            postParams = {}
                            params = re.sub("[\"\+]","",params)
                            for p in params.split("&"):
                                if "=" in p:
                                    key, value = p.split("=")
                                    postParams[key] = value
                                    keywords.add(key)
                        pRes = "{}, {}".format(cgi, postParams)

                        if not pRes in resList:
                            resList.append(pRes)

    #save match results to files
    resFile = "./{}/{}/cgiParams.csv".format(vendor, model)
    if resList:
        list2file(resList, resFile)
        print("CGI params has been writen to {}".format(resFile))
    else:
        print("No cgi is found!")
        return 0

    with open(resFile, "a") as f:
        f.write("\nkeywords:\n{}".format(list(keywords)))

    #save match results to database
    conn = sqlite3.connect("./{}/{}/cgiFilter.db3".format(vendor, model))
    cursor = conn.cursor()
    mkTables(cursor, conn)
    cgiId = 0
    paramID = 0
    for res in resList:
        cgi = res[:res.index(",")]
        params = res[res.index(",") + 1:]
        #deal with CGI
        cgi = re.sub("['\"]","",cgi)
        if cgi.startswith("path+"):
            cgi = cgi.replace("path+", "/app/safety_wireless/webs/")# fix for G1 and F5C
        cgiId += 1
        cursor.execute("insert into cgis values ({}, '{}')".format(cgiId, cgi))

        #deal with params, output is dictory
        if "{" in params:
            params = re.sub("[\\{\\}\\s]", "", params)
            if not params:#params is {}
                continue
            params = re.sub("\(.*\)","\(\)", params)
            for key_val in params.split(","):
                key, val = key_val.split(":")
                if "'" in val or "\"" in val or val.isdigit():
                    value = re.sub("['\"]", "", val)
                    cls = ""
                elif val:
                    value = ""
                    cls = val
                paramID += 1
                cursor.execute("insert into params values ({}, {}, '{}', '{}', '', '{}', '')".format(paramID, cgiId, re.sub("['\"]", "", key), value, cls))
        elif "[" in params:
            #we need to get param from context
            params = re.sub("[\\[\\]\\s']", "", params)
            for p in params.split(","):
                paramID += 1
                cursor.execute(
                    "insert into params values ({}, {}, '{}', '', '', '', '')".format(paramID, cgiId, p))

    conn.commit()
    conn.close()

def extractCgiParams(key, text):
    pattern1 = "\\b"+key+"\\s*=\\s*\{\\s*\};"
    pattern2 = "\\b"+key+"\\s*=\\s*new\\sObject;"
    pattern3 = "\\b"+key+"\\s*=\\s*\\{([^\\}]+)\\};"
    if re.findall(pattern1, text) or re.findall(pattern2, text):
        values = re.findall("\\b{}\\.(\\w+)\\b".format(key), text)
        res = set()
        for v in values:
            res.add(v)
        return "list", list(res)
    elif re.findall(pattern3, text):
        dicts = re.findall(pattern3, text)
        if dicts:
            res_dict = {}
            for d in dicts:
                dict = re.sub("\\s", "", d)
                for key_value in dict.split(","):
                    if ":" in key_value:
                        key, value = key_value.split(":")
                        res_dict[key] = value
                # res_dict.update(dict)
            return "dict", res_dict
    return "str", key

def getParams4Cgi(html):
    try:
        html_content = open(html, errors="ignore").read()
    except Exception as e:
        print("Error {} in open {}".format(e, html))
        return [], []
    try:
        xhtml = etree.HTML(html_content)
    except Exception as e:
        print("Error {} in parsing {}".format(e, html))
        xhtml = None
    if xhtml is None:
        return [], []
    form = xhtml.xpath('//form')
    action = []
    input_list = []

    if len(form):
        for f in form:
            action.append(f.attrib.get('action',''))

        inputs = xhtml.xpath('//input')
        for i in inputs:
            input_list.append((i.attrib.get('name',''), i.attrib.get('value',''), i.attrib.get('type',''), i.attrib.get('class',''), i.attrib.get('maxlength','')))

    return action, input_list

#inputs: [(name, value, type, class, maxlength)]
def diffRequest(url, inputs):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36"}
    proxies = {"http": "socks5://127.0.0.1:1088",'https': 'socks5://127.0.0.1:1088'}
    # proxies = {}
    try:
        r = requests.get(url, headers=headers, timeout=3, proxies=proxies)
        unparaRsps = r.content
    except Exception as e:
        unparaRsps = b'Error: ' + str(e).encode()
    try:
        payload = {}
        for input in inputs:
            key = input[0]
            cls = input[3]
            if not key:
                continue
            if input[1] and not re.findall("[\.<\(]", input[1]):
                value = input[1]
            elif cls == 'num':
                value = '0'
            elif re.match("addr", key):
                value = "192.168.0.100"
            elif re.match("mask", key):
                value = "255.255.255.0"
            elif re.match("gateway", key):
                value = "192.168.0.1"
            elif re.match("mac", key, re.I):
                value = "24:41:8C:01:2F:7E"
            elif re.match("username", key, re.I):
                value = "usertest"
            elif re.match("pass", key, re.I):
                value = "usertest123"
            elif re.match("dns", key, re.I):
                value = "8.8.8.8"
            elif re.match("dst", key, re.I):
                value = "127.0.0.1"
            else:
                value = 'some'
            payload[key] = value
        r = requests.post(url, data=payload, headers=headers, timeout=3)
        paraRsps = r.content
    except Exception as e:
        paraRsps = b'null'
    return base64.b64encode(unparaRsps), base64.b64encode(paraRsps), payload

def htmlCgiParams(vendor, model):
    print("Finding post cgi from html : {} {}".format(vendor, model))
    dbFile = "./{}/{}/cgiFilter.db3".format(vendor, model)
    conn = sqlite3.connect(dbFile)
    cursor = conn.cursor()
    mkTables(cursor, conn)
    scanDir = "./{}/{}/firmware/www".format(vendor, model)
    htmls = []
    actionID = 0
    inputID = 0
    resList = []

    for root, dirs, files in os.walk(scanDir):
        for name in files:
            if name.endswith(".htm"):
                htmls.append(os.path.join(root, name))
    keywords = set()
    for html in htmls:
        action, input_list = getParams4Cgi(html)
        for a in action:
            if not a or "<" in a:
                continue
            actionID += 1
            cursor.execute("insert into cgis values ({}, '{}')".format(actionID, a))

            params = {}
            for i in input_list:
                inputID += 1
                cursor.execute("insert into params values ({}, {}, '{}', '{}', '{}', '{}', '{}')".
                               format(inputID, actionID, i[0], i[1], i[2], i[3], i[4]))
                params[i[0]] = i[1]
                keywords.add((i[0]))
            resStr = "{}, {}".format(a, str(params))
            if not resStr in resList:
                resList.append(resStr)

    conn.commit()
    conn.close()

    #save data in csv
    resFile = "./{}/{}/cgiParams.csv".format(vendor, model)
    if resList:
        list2file(resList, resFile)
        print("CGI params has been writen to {}".format(resFile))
    else:
        print("No form is found!")

    with open(resFile, "a") as f:
        f.write("\nkeywords:\n{}".format(list(keywords)))

def mkDiffRequests(vendor, model, base_url):
    dbFile = "./{}/{}/cgiFilter.db3".format(vendor, model)
    conn = sqlite3.connect(dbFile)
    cursor = conn.cursor()

    cgis = cursor.execute("select * from cgis").fetchall()
    reqID = 0
    for c in cgis:
        cgiID = c[0]
        cgi = c[1]
        url = urljoin(base_url, cgi)
        print(url)
        params = cursor.execute("select name, defaultValue, type, class, maxlength from params where cgiID={}".format(cgiID)).fetchall()
        unparaRsps, paraRsps, payload = diffRequest(url, params)
        if unparaRsps == paraRsps:
            diff = "False"
        else:
            diff = "True"
        cursor.execute("insert into requests values ({}, '{}', '', '{}', '{}')".format(reqID + 1, url, unparaRsps.decode(), diff))
        cursor.execute(
            "insert into requests values ({}, '{}', \"{}\", '{}', '{}')".format(reqID + 2, url, payload, paraRsps.decode(), diff))
        reqID += 2
    conn.commit()
    conn.close()

def listDiffCgi(vendor, model):
    dbFile = "./{}/{}/cgiFilter.db3".format(vendor, model)
    conn = sqlite3.connect(dbFile)
    cursor = conn.cursor()
    requests = cursor.execute("select url, payload, response from requests where diff='True'").fetchall()
    with open("./{}/{}/unauthSetting.log.txt".format(vendor, model), "w") as f:
        for req in requests:
            url = req[0]
            payload = req[1]
            resp = base64.b64decode(req[2]).decode()
            f.write("Url:\t{}\nPayload:\t{}\nresponse:\t{}\n".format(url, payload, resp))
            f.write("-"*100 + "\n")
    print("param and unparam reps hav been saved in {}".format(dbFile))

if __name__ == "__main__":
    start = time.time()
    vms = ['Amcrest  IP2M841',  'ASUS AC55U',   'D-Link DIR-868L',      'D-Link DIR-412',   'D-Link DIR-816',
           'D-Link   DAP-1320', 'H3C MAGIC',    'Mercury MIPC372-4',    'Mercury MNVR408',  'Nettcore G1',
           'Netgear  PLW1000',  'Netgear W104', 'Netgear  WNDR4000',    'Qihoo360 F5C',     'Tenda    G103',
           'TP-Link  GP110',    'Wavlink AC1200']
    urlDIct = {"G1":"http://192.168.1.1", "F5C":"http://192.168.0.1", "WNDR4000": "http://192.168.1.1",
               "DIR-412":"http://31.170.175.40:3390/", "G103": "http://192.168.1.11/", "WNDR4000": "http://192.168.1.1/"}
    firmadyne = False
    vms = ["Netgear  WNDR4000"]
    for vm in vms:
        vendor, model = vm.split()
        filterInfoLeak(vendor, model, False)

        ajaxCgiParams(vendor, model)
        htmlCgiParams(vendor, model)

        base_url = urlDIct[model]
        mkDiffRequests(vendor, model, base_url)
        listDiffCgi(vendor, model)

    print("Time cost: {}s".format(time.time()-start))
