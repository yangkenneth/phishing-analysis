## ECE 6612 (Computer Network Security)

Phishing Sites: Build a seed list of phising domains that are updated daily, and show trends in lifetime of the average phishing page. 

### Dependencies

Mongo DB
`sudo apt-get install mongodb`

Scrapy
`pip install scrapy`

Scrapyd (for hosting the spiders on the local machine)
`pip install scrapyd`

Pymongo 
`pip install pymongo`

### Example: to run Scrapy and output all outbound links found on a page to a csv file

`scrapy runspider crawler.py -o links.csv -t csv`

**Start Script:**\
Under User Home Directory:
```bash
git clone https://github.com/yangkenneth/ECE-6612.git
```
