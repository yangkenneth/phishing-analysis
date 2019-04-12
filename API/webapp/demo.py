from featureExtraction import UsefulFeatures
url = 'https://cash-fly.com'

features = UsefulFeatures(url)
print(features.predict())