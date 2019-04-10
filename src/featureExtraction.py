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
from urllib.parse import urlparse, urlencode
import whois
from bs4 import BeautifulSoup
import requests
import urllib.request
from urllib.error import HTTPError
from datetime import datetime
import csv
import pandas as pd
from itertools import islice
from database import Database
from crawl import Url
from crawl import UpdateUrl
import argparse

## This class contains methods that gets url and return useful featrues
class UsefulFeatures(object):
    def __init__(self, url):
        self.url = url

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
                        if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
                            try:
                                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
                            except:
                                return -1
                        registration_length += abs((expiration_date - creation_date).days)

                    return int(registration_length / len(creation_dates))
                else:
                    creation_date = domain_name.creation_date
                    expiration_date = domain_name.expiration_date
                    if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
                        try:
                            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
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
                        if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
                            try:
                                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
                            except:
                                return 1
                        registration_length += abs((expiration_date - today).days)

                    return int(registration_length / len(creation_dates))
                else:
                    creation_date = domain_name.creation_date
                    expiration_date = domain_name.expiration_date
                    if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
                        try:
                            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
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
            return 1  # does not have https
        else:
            return 0  # potential legitimate

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
        flag = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', self.url)  # Ipv6
        if flag:
            return 1  # phishing
        else:
            return 0  # legitimate

    # The Url includes direct IP address or not
    def getHaveIpAddress(self):
        """
        :rtype: int
        """
        flag = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', self.url)  # Ipv6
        if flag:
            return 1  # phishing
        else:
            return 0  # legitimate

    # The Url includes '@' symbol or not
    def getHaveAtSymbol(self):
        """
        :rtype: int
        """
        m = re.search('@', self.url)
        if m == None:
            return 0  # legitimate
        else:
            return 1  # phishing

    # The Url includes '//' redirect or not
    def getIfRedirects(self):
        if "//" in urlparse(self.url).path:
            return 1  # phishing
        else:
            return 0  # legitimate

    # The Url uses shortenUrl service or not
    def getIsShortenUrl(self):
        """
        :rtype: int
        """
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',
                          self.url)
        if match:
            return 1  # phishing
        else:
            return 0  # legitimate

    # The Url has low website traffic or not, from Alexa database
    def getWebTrafficAlexa(self):
        """
        :rtype: int
        """
        try:
            rank = \
                BeautifulSoup(
                    urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(),
                    "xml").find("REACH")['RANK']
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


    def getHTMLContent(self, args):
        url = Url(0, self.url)
        UpdateUrl(args).update_url_content(url)
        return url.get_content()

    def get_content_features(self, args):
        website_metric = {}
        db_content = str(self.getHTMLContent(args))
        if db_content != 'None':
            count = 0
            cnt = 0
            soup = BeautifulSoup(db_content, 'html.parser')
            tmp = soup.find_all('div')
            password = soup.findAll('input', {'type': 'password'})
            for input in password:
                count = count + 1
            text = soup.findAll('input', {'type': 'text'})
            for input in text:
                count = count + 1
            for i in tmp:
                t2 = i.get('onclick')
                if t2 is not None:
                    cnt += 1
            website_metric['text_length'] = len(soup.get_text())
            website_metric['num_onclick'] = cnt
            website_metric['num_of_form'] = count
        return website_metric


    def getFeatureSummary(self, args):
        URL = self.url
        whoisRes = self.WhoisQuery()
        ageOfDomain = whoisRes[1]
        hasHttps = self.getHasHttps()
        urlLength = self.getUrlLength()
        prefixSuffix = self.getPrefixSuffix()
        hasIP = self.getHaveIpAddress()
        hasAt = self.getHaveAtSymbol()
        redirects = self.getIfRedirects()
        shortenUrl = self.getIsShortenUrl()
        domainRegLength = whoisRes[2]
        DNSrecord = whoisRes[0]
        webTraffixAlexa = self.getWebTrafficAlexa()
        multSubDomains = self.getMultSubdomains()

        data = {'URL': URL, 'ageOfDomain': ageOfDomain, 'hasHttps': hasHttps, 'urlLength': urlLength,
                'prefixSuffix': prefixSuffix, 'hasIP': hasIP, 'hasAt': hasAt, 'redirects': redirects,
                'shortenUrl': shortenUrl, 'domainRegLength': domainRegLength, 'DNSrecord': DNSrecord,
                'webTraffixAlexa': webTraffixAlexa, 'multSubDomains': multSubDomains}
        data.update(self.get_content_features(args))
        return data

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Hyperparams')
    parser.add_argument('--http_timeout', nargs='?', type=int, default=5,
                        help='timeout for http requests')
    parser.add_argument('--socket_timeout', nargs='?', type=int, default=3,
                        help='timeout for so')
    parser.add_argument('--http_retries', nargs='?', type=int, default=1,
                        help='number of retry counts')
    args = parser.parse_args()
    features = UsefulFeatures('art.com')
    all_features = features.getFeatureSummary(args)
    print(all_features)