# Implementation of APIs for feature extraction given URLs
# Features: https://docs.google.com/spreadsheets/d/19_FFkthASU4f5toscRxBeOzvLe_LpAqNAL_cyCsUxac/edit#gid=0&fvid=976435702
# ---------------
# Returns values: 
# 0 = lowest probability of phishing
# 1 = moderate probability of phishing - only when using 3 thresholds
# 2 = highest probability of phishing
# ---------------

import time
import re
from urllib.parse import urlparse,urlencode
import whois
from bs4 import BeautifulSoup
import requests
import urllib.request
from urllib.error import HTTPError
from datetime import datetime
import csv
import pandas as pd
from itertools import islice
from models.search import Search
from database import Database

## This class contains methods that gets url and return useful featrues
class usefulFeatures(object):
    def __init__(self,url):
        self.url=url

def getInputFields():
    address = Database.find()
    df = pd.DataFrame()

    for var in address:
        if var is not None:
            count = 0
            content = var['url_content']
            url = Search.from_content(content)['url']
            soup = BeautifulSoup(content, "html.parser")
            password = soup.findAll('input', {'type': 'password'})
            for input in password:
                count = count + 1
            text = soup.findAll('input', {'type': 'text'})
            for input in text:
                count = count + 1
            df = df.append({'url': url, 'input_count': count}, ignore_index=True)
    print(df)

    # External objects such as images within a webpage are loaded from another Domain.
    def getReqUrl(self):
        """
        :rtype: bool
        """
        pass

    # URLs created less than 1 year or will expire within the coming 3 months from WHOIS.
    def getAgeOfDomain(self):
        """
        :rtype: int
        """
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

    # The URL includes "https" or not
    def getHasHttps(self):
        """
        :rtype: int
        """
        m = re.search('https', self.url)
        if m == None:
            return 2     # phishing
        else:
            return 0     # potential legitimate

    # The URL https is fake or not, when the URL has "https"
    def getFakeHttps(self):
        """
        :rtype: bool
        """
        pass

    # The Url string length
    def getUrlLength(self):
        """
        :rtype: int
        """
        if len(self.url) < 54:
            return 0
        elif len(self.url)> 75:
            return 2
        else:
            return 1

    # The Url includes how many '-'
    def getPrefixSuffix(self):
        """
        :rtype: int
        """
        m = re.findall('-', self.url)
        return len(m)

    # The Url includes direct IP address or not
    def getHaveIpAddress(self):
        """
        :rtype: int
        """
        flag = re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',self.url)     #Ipv6
        if flag:
            return 2    # phishing
        else:
            return 0    # legitimate

    # The Url includes '@' symbol or not
    def getHaveAtSymbol(self):
        """
        :rtype: int
        """
        m = re.search('@', self.url)
        if m == None:
            return 0   # legitimate
        else:
            return 2   # phishing

    # The Url includes '//' redirect or not
    def getIfRedirects(self):
        if "//" in urlparse(self.url).path:
            return 2            # phishing
        else:
            return 0            # legitimate

    # The Url uses shortenUrl service or not
    def getIsShortenUrl(self):
        """
        :rtype: int
        """
        match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',self.url)
        if match:
            return 2        # phishing
        else:
            return 0        # legitimate


    def getPageRank(self):
        pass

    # The Url domain expires less than 1 year or not
    def getDomainRegLen(self):
        """
        :rtype: int
        """
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

    # The DNS record of Url exists or not
    def getDNSRecordExists(self):
        """
        :rtype: int
        """
        try:
            domain_name = whois.whois(urlparse(self.url).netloc)
            return 0
        except:
            return 2

    # The Url has low website traffic or not, from Alexa database
    def getWebTrafficAlexa(self):
        """
        :rtype: int
        """
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

    # The Url has multiple sub domians or not
    def getMultSubdomains(self):
        """
        :rtype: int
        """
        if self.url.count(".") < 3:
            return 0
        elif self.url.count(".") == 3:
            return 1
        else:
            return 2

    # The Url has '-' or not
    def getHasHiphen(self):
        """
        :rtype: int
        """
        if "-" in urlparse(self.url).netloc:
            return 2    # phishing
        else:
            return 0    # legitimate

    # The domain of anchor(<a> tag) is different from that of the website.
    def getUrlAnchor(self):
        pass

    # Phishers used JavaScript to display a fake URL in the status bar to the users.
    def getOnmouseover(self):
        pass

    # The host name in URL does not match its claimed identity from WHOIS.
    def getAbnormalUrl(self):
        pass

    # The Url Website ask users to submit their credentials through a popup window.
    def getPopUpWidnow(self):
        pass

    # Server Form Handler(SFH) that are empty string or contains "about:blank" are considered doubtful
    def getSFH(self):
        pass

    # Phishers used JavaScript to disable the right click function.
    def getRightClick(self):
        pass

    # '//' redirect should appear on the 6th/7th -http/https if they appear 
    def getDoubleSlashRedirecting(self):
        pass

    # 
    def getSSLFinalState(self):
        pass

    # If favicon loaded from different external domain or not
    def getFavicon(self):
        pass

    # check the port, e.g., xxx.com:8080
    def getPort(self):
        pass

    # https token part of the domain part of url
    def getHTTPSToken(self):
        pass

    def getLinksAndTags(self):
        pass

    def getSubmittingToEmail(self):
        pass

    # get website Page Rank ranking from Google
    def getPageRank(self):
        pass

    # get website Google index
    def getGoogleIndex(self):
        # https://developers.google.com/search/apis/indexing-api/v3/quickstart
        pass


    def getLinksPointingToPage(self):
        pass
    def getStatisticalReport(self):
        pass

#to test your suggested trash method :)
if __name__ == '__main__':
	# run test cases
    testcase1 = "http://www.coc-ga-tech.edu" # <= type url that you wanna test
    testcase2 = "https://tinyurl.com/gatech"
    x=usefulFeatures(testcase1) # intialize the feature extraction class
    getvalue=x.getDomainRegLen() #Todo change this line add your method instead
    print(getvalue) #see the output

    
    # read csv file and output feature csv
    # read first 100 lines for now
    URL = []
    ageOfDomain = []
    hasHttps = []
    urlLength = []
    prefixSuffix = []
    hasIP = []
    hasAt = []
    redirects = []
    shortenUrl = []
    domainRegLength = []
    DNSrecord = []
    webTraffixAlexa = []
    multSubDomains = []
    hasHiphen = []


    with open('phishinginfo.csv') as csvfile:
    	reader = csv.DictReader(csvfile)
    	for i,row in enumerate(reader):
        	currUrl = row['url']
        	allFeatures = usefulFeatures(currUrl)

        	URL.append(currUrl)
        	ageOfDomain.append(allFeatures.getAgeOfDomain())
        	hasHttps.append(allFeatures.getHasHttps())
        	urlLength.append(allFeatures.getUrlLength())
        	prefixSuffix.append(allFeatures.getPrefixSuffix())
        	hasIP.append(allFeatures.getHaveIpAddress())
        	hasAt.append(allFeatures.getHaveAtSymbol())
        	redirects.append(allFeatures.getIfRedirects())
        	shortenUrl.append(allFeatures.getIsShortenUrl())
        	domainRegLength.append(allFeatures.getDomainRegLen())
        	DNSrecord.append(allFeatures.getDNSRecordExists())
        	webTraffixAlexa.append(allFeatures.getWebTrafficAlexa())
        	multSubDomains.append(allFeatures.getMultSubdomains())
        	hasHiphen.append(allFeatures.getHasHiphen())


        	if(i >= 100):
        		break

    # build feature table Dataframe
    data = {'URL':URL,'ageOfDomain':ageOfDomain,'hasHttps':hasHttps,'urlLength':urlLength,'prefixSuffix':prefixSuffix,'hasIP':hasIP,'hasAt':hasAt,'redirects':redirects,'shortenUrl':shortenUrl,'domainRegLength':domainRegLength,'DNSrecord':DNSrecord,'webTraffixAlexa':webTraffixAlexa,'multSubDomains':multSubDomains,'hasHiphen':hasHiphen}
    df = pd.DataFrame(data)
    df.to_csv('features-100.csv')
    # print(df)
    
