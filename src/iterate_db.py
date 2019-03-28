import argparse
from data import access_db

def iterate_collectoion(args):
    tb_inst = access_db.get_table_instance(args.database_name, args.url_table_name)
    for x in tb_inst.find({}, {"_id": 0, "url": args.batch_size, "distance_from_root":args.batch_size, "url_content": args.batch_size}):
        yield (x)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Hyperparams')

    parser.add_argument('--batch_size', nargs='?', type=int, default=15,
                        help='Batch Size')
    parser.add_argument('--database_name', nargs='?', type=str, default='fullstack',
                        help='the name of the Mongo database we will use')
    parser.add_argument('--url_table_name', nargs='?', type=str, default='phishing',
                        help='the name of the ip_table')
    parser.add_argument('--data_loc', nargs='?', type=str, default='~/Desktop/ECE-6612/src/phishing.csv',
                        help='data location')
    parser.add_argument('--cursor', nargs='?', type=int, default=0,
                        help='position to extract info from')
    args = parser.parse_args()
    q = iterate_collectoion(args)

    # to print all uncomment the loop below
    #while(q):
    #    print(next(q))
    print(next(q))
