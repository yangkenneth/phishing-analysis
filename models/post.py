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


    def save_to_mongo(self):
        Database.insert(data=self.json())

    def json(self):
        return {
            'id': self.id,
            'website_id': self.website_id,
            'website_url': self.website_url,
            'content': self.content,
            'date': self.create_date
        }

    @staticmethod
    def from_mongo(id):
        return Database.find_one(query={'id': id})

    @staticmethod
    def from_website(website_id):
        return [post for post in Database.find(query={'website_id': website_id})]
