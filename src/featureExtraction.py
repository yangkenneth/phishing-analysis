# Implementation of APIs for feature extraction given URLs
# Features: https://docs.google.com/spreadsheets/d/19_FFkthASU4f5toscRxBeOzvLe_LpAqNAL_cyCsUxac/edit#gid=0&fvid=976435702
# ---------------
# Returns values: 
# 0 = lowest probability of phishing
# 1 = moderate probability of phishing - only when using 3 thresholds
# 2 = highest probability of phishing
# ---------------

import re
from urllib.parse import urlparse,urlencode
import whois
from bs4 import BeautifulSoup
import requests
import urllib.request
from urllib.error import HTTPError
from datetime import datetime

## TODO
def getReqUrl(url):
    pass

def getAgeOfDomain(url):
    try:
        domain_name = whois.whois(urlparse(url).netloc)
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
            try:
                creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
            except:
                return 1
        if ((expiration_date is None) or (creation_date is None)):
            return 2
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 1
        else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain/30) < 6):
                return 2
            else:
                return 0
    except:
        return 2

def getHasHttps(url):
    m = re.search('https', url)
    if m == None:
        return "noHttps"
    else:
        return "foundHttps"

def getFakeHttps(url):
    pass


def getUrlLength(url):
    if len(url) < 54:
        return 0            
    elif > 75:
        return 2            
    else:
        return 1            

def getPrefixSuffix(url):
    m = re.findall('-', url)
    return len(m)

def getHaveIpAddress(url):
    flag=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4
                '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)     #Ipv6
    if flag:
        return 2
    else:
        return 0

def getHaveAtSymbol(url):
    m = re.search('@', url)
    if m == None:
        return "no@Symbol"
    else:
        return "found@Symbol"

def getIfRedirects(url):
    if "//" in urlparse(url).path:
        return 2            # phishing
    else:
        return 0            # legitimate

# def getIsShortenUrl(url, service_dict):
#     mList = [re.search(x, url) for x in service_dict]
#     for m in mList:
#         if m != None:
#             return True
#     return False


def getIsShortenUrl(url):
    match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
    if match:
        return 2
    else:
        return 0    

## TODO
def getPageRank(url):
    pass

def getDomainRegLen(url):
    try:
        domain_name = whois.whois(urlparse(url).netloc)
        expiration_date = domain_name.expiration_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        if expiration_date is None:
            return 2
        elif type(expiration_date) is list or type(today) is list :
            return 1
        else:
            creation_date = domain_name.creation_date
            expiration_date = domain_name.expiration_date
            if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
                try:
                    creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                    expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
                except:
                    return 1
            registration_length = abs((expiration_date - today).days)
            if registration_length / 365 <= 1:
                return 2
            else:
                return 0
    except:
        return 2 

def getDNSRecordExists(url):
    try:
        domain_name = whois.whois(urlparse(url).netloc)
        return 0
    except:
        return 2

def getWebTrafficAlexa(url):
    try:
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
    except TypeError:
        return 2
    except HTTPError:
        return 1
    except:
        return 1
    rank= int(rank)
    if (rank<100000):
        return 0
    else:
        return 1

def getNumSubdomains(url):
    if url.count(".") < 3:
        return 0       
    elif url.count(".") == 3:
        return 1
    else:
        return 2

def getHasHiphen(url):
    if "-" in urlparse(url).netloc:
        return 2
    else:
        return 0

# service_dict = {'brand.link', 'bit.ly', 'tiny.url', 'tinyurl.com', 'tiny.cc', 'lc.chat', 'is.gd', 'soo.gd', 's2r.co', 'clicky.me', 'budurl.com'}
# testcase = "http://www.coc-ga-tech.edu"
# testcase2 = "https://tinyurl.com/gatech"

# print(getPrefixSuffix(testcase))
# print(getIsShortenUrl(testcase, service_dict))
# print(getIsShortenUrl(testcase2, service_dict))
