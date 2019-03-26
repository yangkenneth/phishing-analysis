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




