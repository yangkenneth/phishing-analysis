from database import Database


class Search(object):
    @staticmethod
    def get_timestamp(timestamp):
        return Database.find_one(query={'timestamp': timestamp})

    @staticmethod
    def get_id(global_id):
        return Database.find_one(query={'global_id': global_id})

    @staticmethod
    def get_url(url):
        return Database.find_one(query={'url': url})

    @staticmethod
    def get_ip_address(ip_address):
        return Database.find_one(query={'ip_address': ip_address})

    @staticmethod
    def get_root_url(root_url):
        return Database.find_one(query={'root_url': root_url})

    @staticmethod
    def get_parent_object(parent_url):
        return Database.find_one(query={'parent_url': parent_url})

    @staticmethod
    def get_distance_from_root(distance_from_root):
        return Database.find_one(query={'distance_from_root': distance_from_root})

    @staticmethod
    def get_url_content(url_content):
        return Database.find_one(query={'parent_url': url_content})

    # @staticmethod
    # def certificate_count(check_certificate):
    #     count = 0
    #     for post in Database.find(query={'check_certificate': check_certificate}):
    #         count = count + 1
    #     return count




