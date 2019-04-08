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
                distance = Search.from_url(url)['distance_from_root']

                soup = BeautifulSoup(content, "html.parser")
                password = soup.findAll('input', {'type': 'password'})
                for input in password:
                    count = count + 1
                text = soup.findAll('input', {'type': 'text'})
                for input in text:
                    count = count + 1
                df = df.append({'url': url, 'input_count': count, 'distance': distance}, ignore_index=True)
        print(df)

    # External objects such as images within a webpage are loaded from another Domain.
    def getReqUrl(self):
        """
        :rtype: bool
        """
        pass

    # Returns: (DNSRecordExists, AgeOfDomain, DomainRegLen)
    # DNSRecordExists: 0-exists, 2-doesn't
    # AgeOfDomain: 0->1 year, 2-<=1 year or doesn't exist in whois
    # DomainRegLen: 0->1 year, 2-<=1 year or doesn't exist in whois
    def WhoisQuery(self):
        """
        :rtype: (int,int,int)
        :returns: (DNSRecordExists, AgeOfDomain, DomainRegLen)
        """
        def getDomainRegLen(domain_name):
            """
            :rtype: int
            """
            try:
                expiration_date = domain_name.expiration_date
                creation_date = domain_name.creation_date
                today = time.strftime('%Y-%m-%d')
                today = datetime.strptime(today, '%Y-%m-%d')
                if expiration_date is None or creation_date is None:
                    return -1
                elif type(expiration_date) is list:
                    creation_dates = domain_name.creation_date
                    expiration_dates = domain_name.expiration_date
                    registration_length = 0
                    for i in range(len(creation_dates)):
                        creation_date = creation_dates[i]
                        expiration_date = expiration_dates[i]
                        if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
                            try:
                                creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
                            except:
                                return -1
                        registration_length += abs((expiration_date - creation_date).days)
                        
                    return int(registration_length/len(creation_dates))
                else:
                    creation_date = domain_name.creation_date
                    expiration_date = domain_name.expiration_date
                    if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
                        try:
                            creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                            expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
                        except:
                            return -1
                    registration_length = abs((expiration_date - creation_date).days)
                    return int(registration_length)
            except:
                return -1

        def getAgeOfDomain(domain_name):
            """
            :rtype: int
            """
            try:
                expiration_date = domain_name.expiration_date
                today = time.strftime('%Y-%m-%d')
                today = datetime.strptime(today, '%Y-%m-%d')
                if expiration_date is None:
                    return -1
                elif type(expiration_date) is list:
                    creation_dates = domain_name.creation_date
                    expiration_dates = domain_name.expiration_date
                    registration_length = 0
                    for i in range(len(creation_dates)):
                        creation_date = creation_dates[i]
                        expiration_date = expiration_dates[i]
                        if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
                            try:
                                creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
                            except:
                                return 1
                        registration_length += abs((expiration_date - today).days)
                        
                    return int(registration_length/len(creation_dates))
                else:
                    creation_date = domain_name.creation_date
                    expiration_date = domain_name.expiration_date
                    if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
                        try:
                            creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                            expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
                        except:
                            return -1
                    registration_length = abs((expiration_date - today).days)
                    return int(registration_length)
            except:
                return -1
        try:
            domain_name = whois.whois(urlparse(self.url).netloc)
            AgeOfDomain = getAgeOfDomain(domain_name)
            DomainRegLen = getDomainRegLen(domain_name)
            return (0, AgeOfDomain, DomainRegLen)
        except:
            return (1, -1, -1)

    # The URL includes "https" or not
    def getHasHttps(self):
        """
        :rtype: int
        """
        if self.url[0:5] != 'https':
            return 1     # does not have https
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
        return len(self.url)

    # The Url includes how many hiphen '-'
    def getPrefixSuffix(self):
        """
        :rtype: int
        """
        return self.url.count("-")

    # The Url includes direct IP address or not
    def getHaveIpAddress(self):
        """
        :rtype: int
        """
        flag = re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',self.url)     #Ipv6
        if flag:
            return 1    # phishing
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
            return 1   # phishing

    # The Url includes '//' redirect or not
    def getIfRedirects(self):
        if "//" in urlparse(self.url).path:
            return 1            # phishing
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
            return 1        # phishing
        else:
            return 0        # legitimate


    def getPageRank(self):
        pass

#    # The Url domain expires less than 1 year or not
#    def getDomainRegLen(self):
#       """
#       :rtype: int
#       """
#       try:
#          domain_name = whois.whois(urlparse(self.url).netloc)
#          expiration_date = domain_name.expiration_date
#          today = time.strftime('%Y-%m-%d')
#          today = datetime.strptime(today, '%Y-%m-%d')
#          if expiration_date is None:
#             return 2
#          elif type(expiration_date) is list or type(today) is list :
#             return 1
#          else:
#             creation_date = domain_name.creation_date
#             expiration_date = domain_name.expiration_date
#             if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
#                try:
#                   creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
#                   expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
#                except:
#                   return 1
#             registration_length = abs((expiration_date - today).days)
#             if registration_length / 365 <= 1:
#                return 2
#             else:
#                return 0
#       except:
#          return 2

#    # The DNS record of Url exists or not
#    def getDNSRecordExists(self):
#       """
#       :rtype: int
#       """
#       try:
#          domain_name = whois.whois(urlparse(self.url).netloc)
#          return 0
#       except:
#          return 2

    # The Url has low website traffic or not, from Alexa database
    def getWebTrafficAlexa(self):
        """
        :rtype: int
        """
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(), "xml").find("REACH")['RANK']
        except TypeError:
            return -1
        except HTTPError:
            return -2
        except:
            return -3
        rank = int(rank)
        return rank

    # The Url has multiple sub domians or not
    def getMultSubdomains(self):
        """
        :rtype: int
        """
        return self.url.count(".")

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

    def getFeatureSummary(self):
        URL = this.url
        whoisRes = this.WhoisQuery()
        ageOfDomain = whoisRes[1]
        hasHttps = this.getHasHttps()
        urlLength = this.getUrlLength()
        prefixSuffix = this.getPrefixSuffix()
        hasIP = this.getHaveIpAddress()
        hasAt = this.getHaveAtSymbol()
        redirects = this.getIfRedirects()
        shortenUrl = this.getIsShortenUrl()
        domainRegLength = whoisRes[2]
        DNSrecord = whoisRes[0]
        webTraffixAlexa = this.getWebTrafficAlexa()
        multSubDomains = this.getMultSubdomains()

        data = {'URL':URL,'ageOfDomain':ageOfDomain,'hasHttps':hasHttps,'urlLength':urlLength,'prefixSuffix':prefixSuffix,'hasIP':hasIP,'hasAt':hasAt,'redirects':redirects,'shortenUrl':shortenUrl,'domainRegLength':domainRegLength,'DNSrecord':DNSrecord,'webTraffixAlexa':webTraffixAlexa,'multSubDomains':multSubDomains}
        return data

#to test your suggested trash method :)
if __name__ == '__main__':
    # run test cases
    # testcase1 = "http://www.coc-ga-tech.edu" # <= type url that you wanna test
    # testcase2 = "https://tinyurl.com/gatech"
    # x=usefulFeatures(testcase1) # intialize the feature extraction class
    # getvalue=x.getDomainRegLen() #Todo change this line add your method instead
    # print(getvalue) #see the output

    
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

    #please specify input filename here
    urlFileName = 'alexa0_5000.csv'

    with open(urlFileName) as csvfile:
        reader = csv.DictReader(csvfile)
        for i,row in enumerate(reader):
            currUrl = row['url']
            # add http:// prefix if it does not have this
            if (len(currUrl) <= 7 or (currUrl[0:7] != 'http://' and currUrl[0:8] != 'https://')):
                currUrl = 'http://' + currUrl
            print(currUrl)
            allFeatures = usefulFeatures(currUrl)

            URL.append(currUrl)
            whoisRes = allFeatures.WhoisQuery()
            DNSrecord.append(whoisRes[0])
            ageOfDomain.append(whoisRes[1])
            domainRegLength.append(whoisRes[2])
            
            hasHttps.append(allFeatures.getHasHttps())
            urlLength.append(allFeatures.getUrlLength())
            prefixSuffix.append(allFeatures.getPrefixSuffix())
            hasIP.append(allFeatures.getHaveIpAddress())
            hasAt.append(allFeatures.getHaveAtSymbol())
            redirects.append(allFeatures.getIfRedirects())
            shortenUrl.append(allFeatures.getIsShortenUrl())
            
            webTraffixAlexa.append(allFeatures.getWebTrafficAlexa())
            multSubDomains.append(allFeatures.getMultSubdomains())
            
            print("generated features for entry ", i)
            # top k/full list
            # if(i >= 10):
            #     break

    # build feature table Dataframe
    data = {'URL':URL,'ageOfDomain':ageOfDomain,'hasHttps':hasHttps,'urlLength':urlLength,'prefixSuffix':prefixSuffix,'hasIP':hasIP,'hasAt':hasAt,'redirects':redirects,'shortenUrl':shortenUrl,'domainRegLength':domainRegLength,'DNSrecord':DNSrecord,'webTraffixAlexa':webTraffixAlexa,'multSubDomains':multSubDomains}
    df = pd.DataFrame(data)
    # please specify output filename here
    df.to_csv('features-alexa0_5000.csv')
    # print(df)
    
