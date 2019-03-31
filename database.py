import pymongo


class Database(object):
    URI = "mongodb://127.0.0.1:27017/"
    DATABASE = None
    COLLECTIONS = None

    @staticmethod
    def initialize(database, collection):
        client = pymongo.MongoClient(Database.URI)
        Database.DATABASE = client[database]
        Database.COLLECTIONS = Database.DATABASE[collection]

    @staticmethod
    def insert(data):
        Database.COLLECTIONS.insert(data)

    @staticmethod
    def find(query):
        return Database.COLLECTIONS.find(query)

    @staticmethod
    def find():
        return Database.COLLECTIONS.find({})

    @staticmethod
    def find_one(query):
        return Database.COLLECTIONS.find_one(query)

    @staticmethod
    def total_entries():
        return Database.COLLECTIONS.count()
