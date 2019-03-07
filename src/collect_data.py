import pandas as pd

CSV_URL = '/home/joseph/Desktop/Dev/ECE-6612/data/phishtank_urls.csv'

def extract_batches(pos, batch_sz):
    df = pd.read_csv(CSV_URL)
    if pos > df.shape[0]:
        raise (StopIteration('data exceeded!'))
    else:
        return df['url'][pos:pos+batch_sz]
