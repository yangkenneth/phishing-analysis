#from database import Database
#from models.post import Post
#Database.initialize('fullstack', 'phishing')

import scrapy
from scrapy.item import Item, Field
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule

class Link(scrapy.Item):
    url_from = Field()
    url_to = Field()


# example Scrapy crawler
class PhishingSiteSpider(scrapy.Spider):
    name = 'phishing_site_spider'
    start_urls = [
        'http://www.gatech.edu'
    ]

    rules = Rule(LinkExtractor(canonicalize=True, unique=True), callback='parse', follow=False)
    
    # all outbound links
    def parse(self, response):
        items = []
        links = LinkExtractor(canonicalize=True, unique=True).extract_links(response)

        for ref in links:
            item = Link()
            item['url_from'] = response.url
            item['url_to'] = ref.url
            items.append(item)
        
        return items

# POST
# post = Post('ID', "WEBSITE_ID", "WEBSITE_URL", "CONTENT", "DATE")
# post.save_to_mongo()

# GET
# post = Post.from_mongo("ID")
# print(post)

# post = Post.from_website("WEBSITE_ID")
# print(post)
