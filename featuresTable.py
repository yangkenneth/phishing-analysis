from database import Database
from src.featureExtraction import usefulFeatures

## This class gets useful features and stores them in the same database but different collection


class PostFeatures(object):

    def __init__(self, url):
        x=usefulFeatures(url)
        self.Request_URL=x.getReqUrl()
        self.age_of_domain=x.getAgeOfDomain()
        self.has_https=x.getHasHttps()
        self.no_or_fake_HTTPS=x.getFakeHttps()
        self.web_traffic=x.getWebTrafficAlexa()
        self.URL_Length=x.getUrlLength()
        self.having_Sub_Domain=x.getNumSubdomains()
        self.Prefix_Suffix=x.getPrefixSuffix()
        self.URL_of_Anchor=x.getUrlAnchor()
        self.having_IP_Address=x.getHaveIpAddress()
        self.on_mouseover=x.getOnmouseover()
        self.Abnormal_URL=x.getAbnormalUrl()
        self.Redirect=x.getIfRedirects()
        self.popUpWidnow=x.getPopUpWidnow()
        self.DNSRecord=x.getDNSRecordExists()
        self.SFH=x.getSFH()
        self.having_At_Symbol=x.getHaveAtSymbol()
        self.RightClick=x.getRightClick()
        self.Shortining_Service=x.getIsShortenUrl()
        self.double_slash_redirecting=x.getDoubleSlashRedirecting()
        self.SSLfinal_State=x.getSSLFinalState()
        self.Domain_registeration_length=x.getDomainRegLen()
        self.Favicon=x.Favicon()
        self.Port=x.getPort()
        self.HTTPS_token=x.getHTTPSToken()
        self.Links_in_tags=x.getLinksAndTags()
        self.Submitting_to_email=x.getSubmittingToEmail()
        self.Iframe=x.getIframe()
        self.Page_Rank=x.getPageRank()
        self.Google_Index=x.getGoogleIndex()
        self.Links_pointing_to_page=x.getLinksPointingToPage()
        self.Statistical_report=x.getStatisticalReport()

    def save_to_mongo(self):
        Database.insert(data=self.json())

    def json(self):
        return {
            'Request_URL':self.Request_URL,
            'age_of_domain':self.age_of_domain,
            'has_https':self.has_https,
            'no_or_fake_HTTPS':self.no_or_fake_HTTPS,
            'web_traffic':self.web_traffic,
            'URL_Length':self.URL_Length,
            'having_Sub_Domain':self.having_Sub_Domain,
            'Prefix_Suffix':self.Prefix_Suffix,
            'URL_of_Anchor':self.URL_of_Anchor,
            'having_IP_Address':self.having_IP_Address,
            'on_mouseover':self.on_mouseover,
            'Abnormal_URL':self.Abnormal_URL,
            'Redirect':self.Redirect,
            'popUpWidnow':self.popUpWidnow,
            'DNSRecord':self.DNSRecord,
            'SFH':self.SFH,
            'having_At_Symbol':self.having_At_Symbol,
            'RightClick':self.RightClick,
            'Shortining_Service':self.Shortining_Service,
            'double_slash_redirecting':self.double_slash_redirecting,
            'SSLfinal_State':self.SSLfinal_State,
            'Domain_registeration_length':self.Domain_registeration_length,
            'Favicon':self.Favicon,
            'port':self.Port,
            'HTTPS_token':self.HTTPS_token,
            'Links_in_tags':self.Links_in_tags,
            'Submitting_to_email':self.Submitting_to_email,
            'Iframe':self.Iframe,
            'Page_Rank':self.Page_Rank,
            'Google_Index':self.Google_Index,
            'Links_pointing_to_page':self.Links_pointing_to_page,
            'Statistical_report':self.Statistical_report,
        }












if __name__ == '__main__':


    #Database.initialize('fullstack', 'phishing') #initialize the database name and table name


    testcase1 = "http://www.coc-ga-tech.edu"
    testcase2 = "https://tinyurl.com/gatech"
    x=usefulFeatures(testcase1)
    print(x.getPrefixSuffix(),x.getAgeOfDomain(),x.getHasHttps(),x.getUrlLength(),x.getPrefixSuffix(),x.getHaveIpAddress(),x.getHaveAtSymbol(),x.getIfRedirects(),x.getIsShortenUrl(),x.getDomainRegLen(),x.getDNSRecordExists(),x.getWebTrafficAlexa(),x.getNumSubdomains(),x.getHasHiphen())
    #print(getIsShortenUrl(testcase1))
    #print(getIsShortenUrl(testcase2))



