import urllib3
from bs4 import BeautifulSoup
import socket

class Url:
    def __init__(self, id, url):
        """
        This class defines the Url class. Every Url node should have an ipaddress, neigboring links,
        a unique Id assigned on creation of the class instance and a string url

        :param id: A unique Id
        """
        self._root_url = None
        self._ip_address = None
        self._neighbors = {}
        self._id = id
        self._url = url
        self._content = None


    def __str__(self):
        return str('id: {}, url: {}, ip_address: {}'.format(self.get_id(), self.get_url(), self.get_ip_address()))

    def get_url(self):
        return self._url

    def get_id(self):
        return self._id

    def get_ip_address(self):
        """
        This function returns the IPaddress of a URL
        :return: IPaddress
        """
        return self._ip_address

    def get_neighbors(self):
        """

        :return: links found in this Url
        """
        return self._neighbors


    def set_root_url(self, root_url):
        """

        :param root_url: set the parent url in which this url was found
        :return: nothin
        """
        self._root_url = root_url

    def set_ip_address(self, ip_address):
        """

        :param ip_address: set the ip_address value
        :return: nothing
        """
        self._ip_address = ip_address

    def set_neigbors(self, neighbors):
        """

        :param neighbors: set neighboring links
        :return:
        """
        self._neighbors = neighbors

    def set_content(self, content):
        """

        :param content: sets the content of the url
        :return: nothing
        """
        self._content = content


class Crawl:

    def __init__(self, url):
        self.root_ip = None
        self.url = url

class UpdateUrl:

    def __init__(self):
        """
        TODO: Add some attributes later
        """
        pass

    def open_url(self,  Url):
        """
        The function opens the Url
        :param Url: the Url Class
        :return: a BeautifulSoup object
        """
        url = Url.get_url()
        http = urllib3.PoolManager()
        response = http.request('GET', url)
        if response.status not in [200, 320]:
            print('url not found: status-', response.status)
        soup = BeautifulSoup(response.data, 'html.parser')
        return soup

    def extract_links(self, Url):
        """
        the function extracts all the hyperlinks in a webpage
        :param Url:
        :return: a list of hyperlinks
        """
        soup = self.open_url(Url)
        links = []
        for link in soup.find_all('a', href=True):
            temp_link = link.get('href')
            if temp_link.startswith('http'):
                links.append(temp_link)
        return links

    def update_url_neigbors(self, Url):
        """
        This function updates the list of neighbors to a specific Url
        :param Url: the Url class
        :return: nothin
        """
        neighbors = self.extract_links(Url)
        if Url.get_url() in neighbors:
            neighbors.remove(Url.get_url())
        Url.set_neigbors(neighbors)

    def update_url_content(self, Url):
        """
        This function updates the Url content of a page
        :param Url: the Url class
        :return: nothing
        """
        soup = self.open_url(Url)
        Url.set_content = soup.string

    def update_ip_address(self, Url):
        """
        This function updates the ip_address of a page
        :param Url: the Url class
        :return: nothing
        """
        hostname = str(Url.get_url()).split('.')[1:3]
        host = hostname[0]+'.'+hostname[1].split('/')[0]
        ip_address = socket.gethostbyname(host)
        Url.set_ip_address(ip_address)


def main():
    url = Url(0, 'https://www.google.com')
    updates = UpdateUrl()
    updates.update_url_neigbors(url)
    updates.update_url_content(url)
    updates.update_ip_address(url)
    print(url)

if __name__ == '__main__':
    main()


