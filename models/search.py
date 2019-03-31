from database import Database
from bson.objectid import ObjectId


class Search(object):

    @staticmethod
    def from_global_id(global_id):
        return Database.find_one(ObjectId(global_id))

    @staticmethod
    def from_id(generated_id):
        return Database.find_one(query={'global_id': generated_id})

    @staticmethod
    def from_url(url):
        return Database.find_one(query={'url': url})

    @staticmethod
    def from_content(url_content):
        return Database.find_one(query={'url_content': url_content})

    @staticmethod
    def url_content():
        address = Database.find()
        for var in address:
            print(var['url_content'])
