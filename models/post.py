import uuid
from database import Database
from datetime import datetime


class Post(object):

    def __init__(self,id=None, website_id, website_url, content, date=datetime.utcnow()):
        # SELF GENERATE ID
        self.id = uuid.uuid4().hex if id is None else id
        self.website_id = website_id
        self.website_url = website_url
        self.content = content
        self.create_date = date
        self.outbound_urls = outbound_urls
        self.num_symbols_in_url = num_symbols_in_url

    def save_to_mongo(self):
        Database.insert(data=self.json())

    def json(self):
        return {
            'id': self.id,
            'website_id': self.website_id,
            'website_url': self.website_url,
            'content': self.content,
            'date': self.create_date,
            'outbound_urls': self.outbound_urls,
            'num_symbols_in_url' = self.num_symbols_in_url
        }

    @staticmethod
    def from_mongo(id):
        return Database.find_one(query={'id': id})

    @staticmethod
    def from_website(website_id):
        return [post for post in Database.find(query={'website_id': website_id})]
