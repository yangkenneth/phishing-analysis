import argparse
from data import access_db
import pandas as pd
import re
import nltk
from nltk.corpus import brown
import string
from bs4 import BeautifulSoup

def iterate_collection(args):
    tb_inst = access_db.get_table_instance(args.database_name, args.url_table_name)
    for x in tb_inst.find({}, {"_id": 0, "url": args.batch_size, "distance_from_root": args.batch_size, "url_content": args.batch_size}):
        yield (x)

def check_spelling(word_dict, words):
    count = 0
    for word in words:
        if word not in word_dict:
            count += 1
    return count

def run(args):
    q = iterate_collection(args)
    writer = pd.ExcelWriter(args.excel_file)
    website_metric = {'url': [], 'distance': [], 'word_length': [], 'mispelled_words': []}
    word_list = brown.words()
    word_list = list(set(word_list))
    count = 0
    df = pd.DataFrame(columns=['url', 'distance', 'word_length', 'mispelled_words'])
    while(q):
        count += 1
        db_content = next(q)
        #soup = BeautifulSoup(db_content['url_content'], 'html.parser')
        if len(db_content['url_content']) < 2:
            print(db_content['url'])
    #     text = soup.get_text()
    #     words = nltk.word_tokenize(text)
    #     words = [w for w in words if w.isalpha()]
    #     website_metric['url'].append(db_content['url'])
    #     website_metric['distance'].append(int(db_content['distance_from_root']))
    #     website_metric['word_length'].append(len(words))
    #     words = list(set(words))
    #     n_spell_err = check_spelling(word_list, words)
    #     website_metric['mispelled_words'].append(n_spell_err)
    #     if count%10 == 0:
    #         print('{} entries processed'.format(count))
    #         print(website_metric)
    #     if count == args.stop:
    #         break
    # df['url'] = website_metric['url']
    # df['word_length'] = website_metric['word_length']
    # df['mispelled_words'] = website_metric['mispelled_words']
    # df.to_excel(writer, 'Sheet1', index=False)
    # writer.save()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Hyperparams')

    parser.add_argument('--batch_size', nargs='?', type=int, default=15,
                        help='Batch Size')
    parser.add_argument('--database_name', nargs='?', type=str, default='fullstack',
                        help='the name of the Mongo database we will use')
    parser.add_argument('--url_table_name', nargs='?', type=str, default='phishing1',
                        help='the name of the ip_table')
    parser.add_argument('--excel_file', nargs='?', type=str, default='./spell_err.xlsx',
                        help='excel file name')
    parser.add_argument('--stop', nargs='?', type=int, default=1000,
                        help='what iteration to stop')
    args = parser.parse_args()
    run(args)


