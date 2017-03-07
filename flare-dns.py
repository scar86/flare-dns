#!/usr/bin/env python
import sys
import ipgetter
import json
import urllib
import urllib2
import requests
import getopt
import re

logFile="/tmp/flare-dns.log"
flareKey = ''
flareMail = ''
flareDomain = ''
verbose = ''
flareUrl='https://api.cloudflare.com/client/v4/zones'
flareId =''
def get_arg(argv):
    try:
        opts, args = getopt.getopt(argv,"hk:m:d:l:v",["mail=","key=","domain=","log=","verbose="])
    except getopt.GetoptError:
        print 'flare-dns -m <cloudflare-mail> -k <cloudflare-key> -d <domain>'
        print '-l <logfile> default /tmp/flare-dns.log'
        print '-v "verbose output and write to log"'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'flare-dns -m <cloudflare-mail> -k <cloudflare-key> -d <domain>'
            print '-l <logfile> default /tmp/flare-dns.log'
            print '-v "verbose output and write to log"'
            sys.exit()
        elif opt in ("-k", "--key"):
            global flareKey
            flareKey = arg
        elif opt in ("-m", "--mail"):
            global flareMail
            flareMail = arg
        elif opt in ("-d", "--domain"):
            global flareDomain
            flareDomain = arg
        elif opt in ("-l","--log"):
            global logfile
            logFile = arg
        elif opt in ("-v","--verbose"):
            global verbose
            verbose = 'yes'

def log(text):
    if verbose:
        print "{0} ".format(text)
    fh.write(str(text)+" \n")


def dns_info(url):
    log("Getting data from {0}".format(url))
    headers = {'X-Auth-Email': "{0}".format(flareMail), 'X-Auth-Key': "{0}".format(flareKey)}
    r=requests.get(url, headers=headers)
    return r

def exit_script(rc):
    if rc == 0:
        log("Finish execution of script")
        log("")
        fh.close()
    else:
        log("Script failed with RC {0}".format(rc))
        #log("")
        fh.close()
        sys.exit(rc)

def dns_put(zoneid,dnsname,dnsid,ipaddr,type="A"):
        log("Setting dns record to {0}".format(ipaddr))
        full_url="{0}/{1}/dns_records/{2}".format(flareUrl,zoneid,dnsid)
        headers = {'X-Auth-Email': "{0}".format(flareMail), 'X-Auth-Key': "{0}".format(flareKey)}
        param = {'type': "{0}".format(type), 'name': "{0}".format(dnsname), 'content': "{0}".format(ipaddr)}
        r = requests.put(full_url, headers=headers, params=param)
        return r

get_arg(sys.argv[1:])

fh = open(logFile, "a", 0)



if flareDomain and flareMail and flareKey:
    log("Starting execution of script")
    log ("CloudFlare mail: {0}".format(flareMail))
    log ("CloudFlare key: {0}".format(flareKey))
    log ("CloudFlare domain: {0}".format(flareDomain))
else:
    print 'flare-dns.py -m <cloudflare-mail> -k <cloudflare-key> -d <domain>'
    print '-l <logfile> default /tmp/flare-dns.log'
    print '-v "verbose output and write to log"'
    sys.exit()

myip = ipgetter.myip()

log("Current global ip: {0}".format(myip))
urlInfo = dns_info(flareUrl)

if re.search('200', str(urlInfo)):
    data = json.loads(urlInfo.text)
    if data['success']:
        pass
    else:
        log("Query to url returned 200 ok, but responde indicate not successfull")
        log(data)
        exit_script(1)
else:
    log("There was an error getting domain info")
    log(urlInfo.text)
    exit_script(1)

for item in data['result']:
    log(item['name'])
    if item['name'] == flareDomain:
        log("Found requested domain: {0}".format(flareDomain))
        log("{0}: {1}".format(flareDomain,item['id']))
        flareId = item['id']

if flareId :
    pass
else:
    log("Unable to find an ID for requested domain <{0}>".format(flareDomain))
    exit_script(1)

log("Looking for DNS to update")

urlInfo = dns_info("{0}/{1}/dns_records".format(flareUrl,flareId))

if re.search('200', str(urlInfo)):
    data = json.loads(urlInfo.text)
    if data['success']:
        pass
    else:
        log("Query to url returned 200 ok, but responde indicate not successfull")
        log(data)
        exit_script(1)
else:
    log("There was an error getting records info")
    log(urlInfo.text)
    exit_script(1)

for item in data['result']:
    if item['type'] == 'A':
        log("{0}: {1} {2}".format(item['type'],item['name'],item['content']))
        if item['content'] == myip :
            log("Record in sync")
        else:
            log("Need to update record for <{0}> ip is diffent {1} {2}".format(item['name'],item['content'],myip))
            log("Debug : record {0} : {1}".format(item['name'],item['id']))
            urlPut = dns_put(flareId,item['name'],item['id'],myip)
            if re.search('200', str(urlPut)):
                data = json.loads(urlPut.text)
                if data['success']:
                    log("Successfully update record")
                else:
                    log("Query to url returned 200 ok, but responde indicate not successfull")
                    log(data)
                    exit_script(1)
            else:
                log("There was an error updating records ")
                log(urlPut.text)
                exit_script(1)





log("Finish execution of script")
log("")
fh.close()
