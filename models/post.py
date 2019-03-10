from database import Database


class Post(object):

    def __init__(self, timestamp, global_id, url, ip_address, root_url, parent_url, distance_from_root, url_content):
        self.timestamp = timestamp
        self.global_id = global_id
        self.url = url
        self.ip_address = ip_address
        self.root_url = root_url
        self.parent_url = parent_url
        self.distance_from_root = distance_from_root
        self.url_content = url_content

    def save_to_mongo(self):
        Database.insert(data=self.json())

    def json(self):
        return {
            'timestamp': self.timestamp,
            'global_id': self.global_id,
            'url': self.url,
            'ip_address': self.ip_address,
            'root_url': self.root_url,
            'parent_url': self.parent_url,
            'distance_from_root': self.distance_from_root,
            'url_content': self.url_content
        }



