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



## This class contains methods that gets url and return useful featrues

class usefulFeatures(object):
    def __init__(self,url):
        self.url=url



    def getReqUrl(self):
        pass

    def getAgeOfDomain(self):
        try:
            domain_name = whois.whois(urlparse(self.url).netloc)
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

    def getHasHttps(self):
        m = re.search('https', self.url)
        if m == None:
            return "noHttps"
        else:
            return "foundHttps"

    def getFakeHttps(self):
        pass


    def getUrlLength(self):
        if len(self.url) < 54:
            return 0
        elif len(self.url)> 75:
            return 2
        else:
            return 1

    def getPrefixSuffix(self):
        m = re.findall('-', self.url)
        return len(m)

    def getHaveIpAddress(self):
        flag=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',self.url)     #Ipv6
        if flag:
            return 2
        else:
            return 0

    def getHaveAtSymbol(self):
        m = re.search('@', self.url)
        if m == None:
            return "no@Symbol"
        else:
            return "found@Symbol"

    def getIfRedirects(self):
        if "//" in urlparse(self.url).path:
            return 2            # phishing
        else:
            return 0            # legitimate

    # def getIsShortenUrl(url, service_dict):
    #     mList = [re.search(x, url) for x in service_dict]
    #     for m in mList:
    #         if m != None:
    #             return True
    #     return False


    def getIsShortenUrl(self):
        match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',self.url)
        if match:
            return 2
        else:
            return 0

    ## TODO
    def getPageRank(self):
        pass

    def getDomainRegLen(self):
        try:
            domain_name = whois.whois(urlparse(self.url).netloc)
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

    def getDNSRecordExists(self):
        try:
            domain_name = whois.whois(urlparse(self.url).netloc)
            return 0
        except:
            return 2

    def getWebTrafficAlexa(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(), "xml").find("REACH")['RANK']
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

    def getNumSubdomains(self):
        if self.url.count(".") < 3:
            return 0
        elif self.url.count(".") == 3:
            return 1
        else:
            return 2

    def getHasHiphen(self):
        if "-" in urlparse(self.url).netloc:
            return 2
        else:
            return 0

    def getUrlAnchor(self):
        pass

    def getOnmouseover(self):
        pass

    def getAbnormalUrl(self):
        pass
    def getPopUpWidnow(self):
        pass

    def getSFH(self):
        pass
    def getRightClick(self):
        pass
    def getDoubleSlashRedirecting(self):
        pass
    def getSSLFinalState(self):
        pass

    def getFavicon(self):
        pass
    def getPort(self):
        pass

    def getHTTPSToken(self):
        pass
    def getLinksAndTags(self):
        pass
    def getSubmittingToEmail(self):
        pass
    def getPageRank(self):
        pass
    def getGoogleIndex(self):
        pass
    def getLinksPointingToPage(self):
        pass
    def getStatisticalReport(self):
        pass

#to test your suggested trash method :)
if __name__ == '__main__':


    testcase1 = "http://www.coc-ga-tech.edu" # <= type url that you wanna test
    testcase2 = "https://tinyurl.com/gatech"
    x=usefulFeatures(testcase1) # intialize the feature extraction class
    getvalue=x.getDomainRegLen() #Todo change this line add your method instead
    print(getvalue) #see the output