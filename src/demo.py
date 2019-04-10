from featureExtraction import UsefulFeatures

def getAllFeatures(url):
    features = UsefulFeatures(url)
    feature_dict = features.getFeatureSummary()