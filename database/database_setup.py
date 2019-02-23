from sqlalchemy import *

#make sure you have sqlite3 installed on your system for this to work.
engine = create_engine('sqlite:///urls.db')

metadata = MetaData()

# main entry for source URLs (the url from phish tank where Scrapy will start)
# the source URL will be used as the primary key for this table
url_entry = Table('url_entry', metadata,
        Column('url', String(1000), primary_key=True),
        Column('time_stamp', String(50), nullable=False),
        Column('number_links', Integer),
        Column('registered', Boolean, nullable=False),
        Column('number_symbols_in_url', Integer))


# table to hold the urls that Scrapy finds by branching out from the main one.
# the source URL will be used as the primary key for this table
external_links = Table('external_urls', metadata,
        Column('source_url', String(1000),primary_key=True),
        Column('external_url_1', String(1000)),
        Column('external_url_2', String(1000)),
        Column('external_url_3', String(1000)),
        Column('external_url_4', String(1000)),
        Column('external_url_5', String(1000)))

metadata.create_all(engine)