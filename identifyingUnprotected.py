#!/usr/bin/python
# coding:UTF-8

import difflib
import base64
import time
import sys
import os, hashlib
from traceback import print_exc
from urllib.parse import urljoin, quote, unquote
import sqlite3


def string_similar(s1, s2):
    return difflib.SequenceMatcher(None, s1, s2).quick_ratio()

def output_list(filename, list):
    with open(filename, 'w') as f:
        for l in list:
            f.write(l.strip() + "\n")
    print("List has been dump into {}".format(filename))

def getMd5(text):
    m = hashlib.md5()
    if type(text) == str:
        m.update(text.encode('utf-8', 'ignore'))
    else:
        m.update(text)
    return m.hexdigest()

def check1(s1, s2, threshold=0.9):
    if string_similar(s1, s2) > threshold:
        return True
    else:
        return False

def check2(s1, s2):
    if getMd5(s1) == getMd5(s2):
    # if len(s1) == len(s2):
        return True
    else:
        return False

def classify(rsps_list, threshold, firmadyne=False, verbose=False):
    print("[+]Classify start ", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))
    classfication = []
    uai_list = []
    rsps_list_copy = rsps_list.copy()
    while rsps_list_copy:
        # for i in range(len(rsps_list_copy)):
        rsp1 = rsps_list_copy[0]
        url1 = unquote(rsp1['url'])
        if verbose:
            print("[*]Size of rsps_list: {}".format(len(rsps_list_copy)))

        newlist = [url1]
        delurl = [rsp1]
        for j in range(1, len(rsps_list_copy)):
            rsp2 = rsps_list_copy[j]
            url2 = unquote(rsp2['url'])

            tmp1 = rsp1['response']
            tmp2 = rsp2['response']

            s1 = base64.b64decode(tmp1).decode('utf-8', 'ignore')
            s2 = base64.b64decode(tmp2).decode('utf-8', 'ignore')

            if check2(s1, s2) or check1(s1, s2, threshold):
                newlist.append(url2)
                delurl.append(rsp2)

        newlist = list(set(newlist))
        for u in delurl:
            del rsps_list_copy[rsps_list_copy.index(u)]
        # print("[*]Second Size of rsps_list: {}".format(len(rsps_list_copy)))
        if verbose:
            print("[+]New list size: {} time:{}".format(len(newlist),
                                                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))))
        uai_list = uai_list + newlist + ['+' * 50]
        classfication.append(len(newlist))

    print('[*]Cluster raw results:', classfication)
    classfication.sort()

    print('[*]Cluster results:', classfication)

    if (threshold != 0.9):
        return classfication

    if firmadyne:
        output_list('./' + vendor + '/' + model + '/uai-firmadyne.txt', uai_list)
    else:
        output_list('./' + vendor + '/' + model + '/uai.txt', uai_list)


def getRsps(vendor, model, firmadyne=False):
    rsps_list = []
    try:
        if firmadyne:
            conn = sqlite3.connect('dbs/{}_{}_firmadyne.db3'.format(vendor, model))
        else:
            conn = sqlite3.connect('dbs/{}_{}.db3'.format(vendor, model))

        cursor = conn.cursor()
        succ = cursor.execute("select url, content from potential")
        for s in succ:
            rsps = {}
            rsps["url"] = s[0]
            rsps["response"] = s[1]
            rsps_list.append(rsps)
        conn.close()
    except:
        pass
    return rsps_list

def getResponse(vendor, model, url):
    conn = sqlite3.connect('dbs/{}_{}.db3'.format(vendor, model))
    cursor = conn.cursor()
    rsps = cursor.execute("select content from potential where url like '{}'".format(url))
    res = ""
    for r in rsps:
        res = base64.b64decode(r[0]).decode()
    print(res)

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
    # vms = ['Netgear 	WNDR4000']
    # You need to change this Boolean Variable
    firmadyne = True

    id = 0
    for vm in vms:
        id += 1
        time_start = time.time()
        vendor, model = vm.split()

        rsps_list = getRsps(vendor, model, firmadyne)
        if not rsps_list:
            continue
        print('[*]{} {} Number of potential page: {}'.format(vendor, model, len(rsps_list)))

        classify(rsps_list, 0.9, firmadyne)

        # res4 = classify(rsps_list, 0.4)
        # res6 = classify(rsps_list, 0.6)
        # res8 = classify(rsps_list, 0.8)
        # with open("cluster_log.txt","a") as fp:
        #     fp.write("{}\t{}\t{}\t{}\n".format(id, res4, res6, res8))

        print("[*]Time cost: %.2fs" % (time.time() - time_start))
        print("-" * 100)

