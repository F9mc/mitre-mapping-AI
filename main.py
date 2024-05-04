import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from nltk import download
from nltk.corpus import stopwords
from sklearn.metrics import accuracy_score
from sklearn.multiclass import OneVsRestClassifier  


from build_dataset import build, MITRE_TACTICS

import neattext as nt
import neattext.functions as nfx


import argparse



# Downlaod stopwords 
download('stopwords')
stop_words = set(stopwords.words('english'))


# Argparse set up
parser = argparse.ArgumentParser(
                    prog='Mitre-Mapping-AI',
                    description='An AI that map rule title with Mitre Att&CK technique ')

parser.add_argument('title', help="The title to map")
parser.add_argument('-b', '--build', action='store_true', help="Use to build the dataset")
parser.add_argument('-s', '--stats', action='store_true', help="Show dataset and model stats")
parser.add_argument('-l', '--link', action='store_true', help="Display the link to the Mitre Att&CK webpage")


def get_mitre_techniques():
    techniques = []
    with open("techniques.txt", "r") as file:
        for l in file.readlines():
            technique = l.replace("\n", "")
            if not technique in techniques:
                techniques.append(technique)
                
    return techniques


def map_usecase_title(usecases: list, stats = False):
    # Load your CSV data
    data = pd.read_csv('mapping.csv')
    
    # Title Noise
    data['usecase'].apply(lambda x:nt.TextFrame(x).noise_scan())
    # Explore For Noise
    data['usecase'].apply(lambda x:nt.TextExtractor(x).extract_stopwords())
    # Explore For Noise
    corpus = data['usecase'].apply(nfx.remove_stopwords)
    
    tfidf = TfidfVectorizer()
    Xfeatures = tfidf.fit_transform(corpus).toarray()
    
    y = data[MITRE_TACTICS]
    
    # Split Data 
    train, test = train_test_split(data,test_size=0.1,random_state=42)
    X_train = train.usecase
    X_test = test.usecase   
    
    use_cases_dict_list = []
    
    for uc in usecases:
        use_cases_dict_list.append({
            "usecase": uc
        })
        
    uc_df = pd.DataFrame(use_cases_dict_list) 
    print(uc_df)
    
    result = []

    for tag in y:
    
        # Define a pipeline combining a text feature extractor with multi lable classifier
        NB_pipeline = Pipeline([
                        ('tfidf', TfidfVectorizer()),
                        ('clf', OneVsRestClassifier(MultinomialNB(
                            fit_prior=True, class_prior=None))),
                    ])

        # train the model using X_dtm & y
        NB_pipeline.fit(X_train, train[tag])

        if stats:
            # compute the testing accuracy
            prediction = NB_pipeline.predict(X_test)
            print(f'Accuracy for {tag} is {accuracy_score(test[tag], prediction)}')
            
            
        # compute the testing accuracy
        prediction_tag = NB_pipeline.predict(uc_df)
        for i in range(len(prediction_tag)):
            if prediction_tag[i] == 1:
                print(tag)
                result.append(tag)
    return result

    
def main():
    args = parser.parse_args()
    
    if args.build:
        print("Building dataset")
        build(args.stats)
    
    usecases = [args.title]
    predictions = map_usecase_title([
        "Windows: HackTool - Mimikatz Execution"
        ], args.stats)   
    print(predictions)

    for i in range(len(predictions)):
        if args.link:
            print(f"https://attack.mitre.org/techniques/{predictions[i].upper()}") 
        else:
            print(predictions[i].upper())
        
    return predictions
    
        
if __name__ == "__main__":
    main()
    