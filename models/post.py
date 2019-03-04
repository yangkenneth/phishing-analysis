import uuid
from database import Database


class Post(object):

    def __init__(self, url, ip_address, timestamp, outbound_link_number, outbound_link_list, check_certificate, page_up, compounded_url, id=None):
        self.url = url
        self.ip_address = ip_address
        self.timestamp = timestamp # SELF GENERATED
        self.outbound_link_number = outbound_link_number # NUM
        self.outbound_link_list = outbound_link_list # LIST
        self.check_certificate = check_certificate # BOOLEAN
        self.page_up = page_up # BOOLEAN
        self.compounded_url = compounded_url #BOOLEAN
        # SELF GENERATE ID
        self.id = uuid.uuid4().hex if id is None else id

    def save_to_mongo(self):
        Database.insert(data=self.json())

    def json(self):
        return {
            'url': self.url,
            'timestamp': self.timestamp,
            'outbound_link_number': self.outbound_link_number,
            'outbound_link_list': self.outbound_link_list,
            'check_certificate': self.check_certificate,
            'page_up': self.page_up,
            'compounded_url': self.compounded_url,
            'id': self.id
        }



