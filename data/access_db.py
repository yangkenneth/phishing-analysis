import argparse
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

DB_URL = 'mongodb://127.0.0.1:27017/'

def connect():
    try:
        client = MongoClient(DB_URL)
        return client
    except (ConnectionFailure) as err:
        print(err)

def create_database(client, databasename):
        my_db = client[databasename]
        return my_db

def check_if_db_exists(database_name):
    dblist = MongoClient().list_database_names()
    if database_name in dblist:
        return True
    else:
        return False

def create_table(db_obj, table_name):
    table = db_obj[table_name]
    return table

def check_if_table_exists(db_obj, table):
    if table in db_obj.list_collection_names():
        return True
    else:
        return False

def create_table_schema(table_obj):
    url = {'time_stamp': 'nil', 'id': 0, 'url': 'www.google.com', 'ip_address': 'nil', 'root_url': 'nil', 'parent_url': 'nil', 'distance_from_root': 0, 'url_content':'nil'}
    status = table_obj.insert_one(url)
    return status.inserted_id

def get_db_instance(database_name):
    client = connect()
    db_inst = client[database_name]
    return db_inst

def get_table_instance(database_name, table_name):
    client = connect()
    db_inst = client[database_name]
    table_inst = db_inst[table_name]
    return table_inst

def query_table(database, table_name, query):
    tb = get_table_instance(database, table_name)
    query_result = tb.find(query)
    return query_result

def insert_into_table(table_obj, dictionary):
    status = table_obj.insert_one(dictionary)
    return status.inserted_id

def delete_entry(table_obj, query):
    table_obj.delete_one(query)
    return True

def delete_table(table_obj):
    table_obj.drop()
    return True

# def main():
#     url = {'url': 'www.google.com', 'ip_address': '126.0.0.1', 'content': 'blah blah blha', 'uptime': '12.00pm', 'neighbors': 'all of us'}
#     database_name = 'phiser_db'
#     table_name = 'url_table'
#     client = connect(DB_URL)
#     db = create_database(client, database_name)
# chk_db = check_if_db_exists(database_name)
# print('does db exist? ', chk_db)
# tb = create_table(db, table_name)
# db = get_db_instance(database_name)
# chk_table = check_if_table_exists(db, table_name)
# #tb = get_table_instance(database_name, table_name)
# print('does table exist? ', chk_table)
# result = query_table(database_name, table_name, {'url':'www.crap.com'})
# for x in result:
#     print(x)
# status = create_table_schema(tb)
# print('was table schema created? ', status)
# status = insert_into_table(tb, url)
# print('was table inserted? ', status)
# if __name__ == '__main__':
#     main()