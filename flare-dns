#!/usr/bin/env python
import sys
import ipgetter
import json
import urllib
import urllib2
import requests
import getopt
import re
from  scarpkg import logStart, logStop, logMsg, Log, get_info, Bot
from pprint import pprint

logPath="/tmp/flare-dns.log"
flareKey = ''
flareMail = ''
flareDomain = ''
flareUrl='https://api.cloudflare.com/client/v4/zones'
flareId =''
flareInfo = ''
verbose = False
Tbot = False

def get_arg(argv):
    try:
        opts, args = getopt.getopt(argv,"hk:m:d:l:I:v",["mail=","key=","domain=","log=","verbose=","info="])
    except getopt.GetoptError:
        print 'flare-dns -m <cloudflare-mail> -k <cloudflare-key> -d <domain>'
        print '-l <logfile> default /tmp/flare-dns.log'
        print '-I <infoFile> file in yaml format with variables'
        print '-v "verbose output and write to log"'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'flare-dns -m <cloudflare-mail> -k <cloudflare-key> -d <domain>'
            print '-l <logfile> default /tmp/flare-dns.log'
            print '-I <infoFile> file in yaml format with variables'
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
            global logPath
            logPath = arg
        elif opt in ("-v","--verbose"):
            global verbose
            verbose = True
        elif opt in ("-I","--info"):
            global flareInfo
            flareInfo = arg


def dns_info(url):
    log.msg("Getting data from {0}".format(url))
    headers = {'X-Auth-Email': "{0}".format(flareMail), 'X-Auth-Key': "{0}".format(flareKey)}
    r=requests.get(url, headers=headers)
    return r

def exit_script(rc):
    if rc == 0:
        log.msg("Finish execution of script")
        log.msg("")
        log.stop(0)
    else:
        log.msg("Script failed with RC {0}".format(rc))
        #log.msg("")
        log.stop(rc)
        sys.exit(rc)

def dns_put(zoneid,dnsname,dnsid,ipaddr,type="A"):
        log.msg("Setting dns record to {0}".format(ipaddr))
        full_url="{0}/{1}/dns_records/{2}".format(flareUrl,zoneid,dnsid)
        log.msg(full_url)
        headers = {"X-Auth-Email": "{0}".format(flareMail), "X-Auth-Key": "{0}".format(flareKey), "Content-Type": "application/json"}
        param = {"type": "{0}".format(type), "name": "{0}".format(dnsname), "content": "{0}".format(ipaddr)}
        log.msg(param)
        r = requests.put(full_url, headers=headers, json=param)
        return r


def main():
    
    myip = ipgetter.myip()
    log.msg("Current global ip: {0}".format(myip))
    urlInfo = dns_info(flareUrl)
    
    if re.search('200', str(urlInfo)):
        data = json.loads(urlInfo.text)
        if data['success']:
            pass
        else:
            log.msg("Query to url returned 200 ok, but responde indicate not successfull")
            log.msg(data)
            exit_script(1)
    else:
        log.msg("There was an error getting domain info")
        log.msg("Verify credentials and domain to update")
        log.msg(urlInfo.text)
        exit_script(1)
    
    for item in data['result']:
        log.msg(item['name'])
        if item['name'] == flareDomain:
            log.msg("Found requested domain: {0}".format(flareDomain))
            log.msg("{0}: {1}".format(flareDomain,item['id']))
            flareId = item['id']
    
    if flareId :
        pass
    else:
        log.msg("Unable to find an ID for requested domain <{0}>".format(flareDomain))
        exit_script(1)
    
    log.msg("Looking for DNS A records to update")
    
    urlInfo = dns_info("{0}/{1}/dns_records".format(flareUrl,flareId))
    
    if re.search('200', str(urlInfo)):
        data = json.loads(urlInfo.text)
        if data['success']:
            pass
        else:
            log.msg("Query to url returned 200 ok, but responde indicate not successfull")
            log.msg(data)
            exit_script(1)
    else:
        log.msg("There was an error getting records info")
        log.msg(urlInfo.text)
        exit_script(1)
    
    for item in data['result']:
        if item['type'] == 'A':
            log.msg("{0}: {1} {2}".format(item['type'],item['name'],item['content']))
            if item['content'] == myip :
                log.msg("Record in sync")
            else:
                log.msg("Need to update record for <{0}> ip is diffent {1} {2}".format(item['name'],item['content'],myip))
                log.msg("Debug : record {0} : {1}".format(item['name'],item['id']))
                urlPut = dns_put(flareId,item['name'],item['id'],myip)
                if re.search('200', str(urlPut)):
                    data = json.loads(urlPut.text)
                    if data['success']:
                        log.msg("Successfully update record")
                        if Tbot:
                            my_bot.msg("Record {0} updated to {1}".format(item['name'],myip))
                    else:
                        log.msg("Query to url returned 200 ok, but responde indicate not successfull")
                        log.msg(data)
                        exit_script(1)
                else:
                    log.msg("There was an error updating records ")
                    log.msg(urlPut.text)
                    exit_script(1)
    log.stop(0)
    sys.exit(0)

if __name__ == "__main__":
    get_arg(sys.argv[1:])
    
    if flareDomain and flareMail and flareKey :
        pass
    elif flareInfo:
        INFO = get_info(flareInfo)
        flareMail = INFO['flaredns']['mail']
        flareDomain = INFO['flaredns']['domain']
        flareKey = INFO['flaredns']['token']
    
    if flareDomain and flareMail and flareKey :
        pass
    else:
        print 'flare-dns.py -m <cloudflare-mail> -k <cloudflare-key> -d <domain>'
        print '-l <logfile> default /tmp/flare-dns.log'
        print '-I <infoFile> file in yaml format with variables'
        print '-v "verbose output and write to log"'
        sys.exit(1)
        
    log = Log(path=logPath,verbose=verbose) #intialze log here, so it will be usable for all the functions
    if INFO['telegram']['token'] and INFO['telegram']['id'] and INFO['telegram']['user']:
        try:
            my_bot=Bot(INFO['telegram']['token'],INFO['telegram']['id'],INFO['telegram']['user'])
            Tbot = True
        except:
            pass
    
    main()
