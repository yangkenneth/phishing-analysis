# Implementation of APIs for feature extraction given URLs
# Features: https://docs.google.com/spreadsheets/d/19_FFkthASU4f5toscRxBeOzvLe_LpAqNAL_cyCsUxac/edit#gid=0&fvid=976435702
import re

## TODO
def getReqUrl(url):
    pass

## TODO
def getAgeOfDomain(url):
    pass

def getHasHttps(url):
    m = re.search('https', url)
    if m == None:
        return "noHttps"
    else:
        return "foundHttps"

## TODO
def getFakeHttps(url):
    pass


def getUrlLength(url, threshold):
    return len(url) > threshold

def getPrefixSuffix(url):
    m = re.findall('-', url)
    return len(m)

## TODO
def getHaveIpAddress(url):
    return false

def getHaveAtSymbol(url):
    m = re.search('@', url)
    if m == None:
        return "no@Symbol"
    else:
        return "found@Symbol"

def getIsShortenUrl(url, service_dict):
    mList = [re.search(x, url) for x in service_dict]
    for m in mList:
        if m != None:
            return True
    return False

## TODO
def getPageRank(url):
    pass

## TODO
def getDomainRegLen(url):
    pass

## TODO
def getDNSRecord(url):
    pass

## TODO
def getWebTrafficAlexa(url):
    pass


service_dict = {'brand.link', 'bit.ly', 'tiny.url', 'tinyurl.com', 'tiny.cc', 'lc.chat', 'is.gd', 'soo.gd', 's2r.co', 'clicky.me', 'budurl.com'}
testcase = "http://www.coc-ga-tech.edu"
testcase2 = "https://tinyurl.com/gatech"

print(getPrefixSuffix(testcase))
print(getIsShortenUrl(testcase, service_dict))
print(getIsShortenUrl(testcase2, service_dict))