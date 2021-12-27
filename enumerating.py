#! /usr/bin/python
# coding:utf-8

import os
import re
import time


web_srv='(httpd|boa|lighttpd|uhttpd|webs|internet|mini_httpd|sonia|switch)$'

def get_string(firmware_tar):
    cmd = 'strings ' + firmware_tar
    result = os.popen(cmd)
    result_str = result.read()
    return result_str


def make_tar(tar_name, dir_name):
    if not os.path.exists(tar_name):
        cmd = 'tar -cvf {} {}'.format(tar_name, dir_name)
        result = os.popen(cmd)
        result_str = result.read()
    return tar_name


def get_file_list(string):
    pattern = re.compile(r'([-\w]+\.(?:cgi|php|asp|html?|xml))')  # |txt
    # pattern = re.compile(r'([-\w]+\.(?:cgi|shtml|php3|phtml|action|php5|jhtml|php4|json|shtm|htaccess|vbs|store|php2|phtm|php~|svn|thtml|xhtm|bhtml|htmls|ghtml|proper|an|appcache|ashx|asp|aspx|bok|cer|cfm|cfml|chm|cshtml|csr|do|fcgi|htm|html|jsp|mht|mhtm|mhtml|oam|page|php|rhtml|rss|vbhtml|xhtml))')
    file_list = pattern.findall(string)
    file_list = list(set(file_list))
    return file_list


def collect_web_files(firmware_dir):
    web_related_dir = "./{}/web".format(firmware_dir)

    if not os.path.exists(web_related_dir):
        os.mkdir(web_related_dir)
    else:
        return web_related_dir

    # cmd1 = 'find ./' + firmware_dir + ' | grep -E "\.cgi$"'
    cmd1 = 'find ./' + firmware_dir + ' | grep -E "[.]htm|[.]cgi|[.]php|[.]asp|[.]js"'
    # cmd1 = 'find ./' + firmware_dir + ' | grep -E "[.]java|[.]class|[.]cgi|[.]shtml|[.]php3|[.]phtml|[.]action|[.]php5|[.]jhtml|[.]php4|[.]json|[.]shtm|[.]htaccess|[.]vbs|[.]store|[.]php2|[.]phtm|[.]php~|[.]svn|[.]thtml|[.]xhtm|[.]bhtml|[.]htmls|[.]ghtml|[.]proper|[.]an|[.]appcache|[.]ashx|[.]asp|[.]aspx|[.]bok|[.]cer|[.]cfm|[.]cfml|[.]chm|[.]cshtml|[.]csr|[.]do|[.]fcgi|[.]htm|[.]html|[.]js|[.]jsp|[.]mht|[.]mhtm|[.]mhtml|[.]oam|[.]page|[.]php|[.]rhtml|[.]rss|[.]vbhtml|[.]xhtml"'
    result1 = os.popen(cmd1)
    result_str1 = result1.read()
    result_list1 = result_str1.split('\n')
    result_list1.pop()
    # print(result_list1)

    cmd2 = "find ./" + firmware_dir + " | grep -E \"%s\"" % web_srv
    result2 = os.popen(cmd2)
    result_str2 = result2.read()
    result_list2 = result_str2.split('\n')
    result_list2.pop()
    # print(result_list2)

    result_list = result_list1 + result_list2

    for cgi in result_list:
        cmd = 'cp {} {}'.format(cgi, web_related_dir)
        result = os.popen(cmd)

    return web_related_dir


def get_path_list(string):
    pattern = re.compile(r'\/(?:[\-_\w]+\/)+')
    all_dir_list = pattern.findall(string)
    # deduplicate
    all_dir_list = list(set(all_dir_list))

    dir_list = []
    sys_dirs=['/etc', '/proc', '/usr', '/var', '/lib', '/dev', '/bin',
              "/mnt", "/sys", "/root", "/tmp", "/home", "/sbin"]
    for a in all_dir_list:
        flag = 1
        for prefix in sys_dirs:
            if a.startswith(prefix):
                flag = 0
        if flag:
            dir_list.append(a)

    dir_list.append("/")
    # deduplicate
    dir_list = list(set(dir_list))
    return dir_list



def get_url_list(dir_list, file_list):
    url_list = []
    for f in file_list:
        for d in dir_list:
            url_list.append(d + f)
    url_list = list(set(url_list))
    return url_list


def output_list(outputfilename, list):
    blacklist = ['/bsw_fail.cgi']
    with open(outputfilename, 'w+') as f:
        for l in list:
            if l not in blacklist:
                f.write(l + "\n")


def generator(vendor, model, verbose=False):
    firmware_dir = "{}/{}".format(vendor, model)
    try:
        if os.path.isdir("./{}/web".format(firmware_dir)):
            os.system("rm -rf ./{}/web".format(firmware_dir))
        if os.path.isfile("./{}/firmware.tar".format(firmware_dir)):
            os.system("rm -rf ./{}/firmware.tar".format(firmware_dir))
        if os.path.isfile("./{}/web.tar".format(firmware_dir)):
            os.system("rm ./{}/web.tar".format(firmware_dir))
    except:
        pass


    fp = open("log.txt", "a")
    fp.write("-------------------- {} --------------------\n".format(firmware_dir))
    if not os.path.exists(firmware_dir):
        print("[-]ERROR")
        return 1
    
    collect_web_files(firmware_dir)
    web_related_string = get_string(
        make_tar("./{}/web.tar".format(firmware_dir), "./{}/web".format(firmware_dir)))
    path_list = get_path_list(web_related_string)
    print('******************* path-number:', len(path_list), '*******************')
    fp.write("path-number: {}\n".format(len(path_list)))
    fp.write(str(path_list) + "\n")
    if verbose:
        print(path_list)

    firmware_tar_string = get_string(
        make_tar("./{}/firmware.tar".format(firmware_dir), "./{}/firmware".format(firmware_dir)))
    file_list = get_file_list(firmware_tar_string)
    print('******************* file-number:', len(file_list), '*******************')
    fp.write("file-number: {}\n".format(len(file_list)))
    fp.write(str(file_list) + "\n")
    if verbose:
        print(file_list)

    url_list = get_url_list(path_list, file_list)
    print('******************* url-number: ', len(url_list), ' *******************')
    fp.write("url-number: {}\n".format(len(url_list)))

    outputfilename = './' + firmware_dir + "/{}.txt".format(firmware_dir.replace("/", "_"))
    output_list(outputfilename, url_list)
    # copyfile(outputfilename, "./Urls/{}.txt".format(firmware_dir.replace("/", "_")))
    fp.close()

if __name__ == "__main__":
    try:
        os.system("rm ./log.txt")
    except:
        pass

    vms = ['Amcrest  IP2M841',
           'ASUS     AC55U',
           'D-link   DIR-868L',
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

    # vms = ['Netgear  WNDR4000']
    for vm in vms:
        time_start = time.time()
        vendor, model = vm.split()
        print("[+]{}".format(vm))

        #generator(vendor, model, True)
        generator(vendor, model)

        print("[*]Time cost: %.2fs" % (time.time() - time_start))
