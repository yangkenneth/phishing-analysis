from database import Database


class Search(object):
    @staticmethod
    def from_mongo(id):
        return Database.find_one(query={'id': id})

    @staticmethod
    def website_url(url):
        return Database.find_one(query={'url': url})

    @staticmethod
    def certificate_count(check_certificate):
        count = 0
        for post in Database.find(query={'check_certificate': check_certificate}):
            count = count + 1
        return count
