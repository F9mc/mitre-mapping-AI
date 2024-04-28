import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import GaussianNB, ComplementNB, BernoulliNB, CategoricalNB
from sklearn import svm
from sklearn.metrics import f1_score, precision_score, recall_score

import yaml
import xmltodict
import os
import csv
import re
import requests
import argparse


# Argparse set up
parser = argparse.ArgumentParser(
                    prog='Mitre-Mapping-AI',
                    description='An AI that map rule title with Mitre Att&CK technique ')

parser.add_argument('title', help="The title to map")
parser.add_argument('-b', '--build', action='store_true', help="Use to build the dataset")
parser.add_argument('-s', '--stats', action='store_true', help="Show dataset and model stats")
parser.add_argument('-l', '--link', action='store_true', help="Display the link to the Mitre Att&CK webpage")

                    

def format_technique(technique: str) -> str:
    return technique.replace("attack.", "").split(".")[0].lower()

def get_mapping_sigma() -> list:
    """Fetch data from the sigma repository

    Returns:
        list: the list of mapping with the format [{"usecase": usecase, "mitre": tag_mitre}]
    """
    mapping = []

    for rootdir in [
        "./sigma/rules/",
        "./sigma/rules-emerging-threats/",
        "./sigma/rules-dfir/",
        "./sigma/rules-placeholder/",
        "./sigma/rules-dfir/",
        "./sigma/rules-threat-hunting/"
    ]:

        # Use os.walk to iterate over the directory tree
        for subdir, dirs, files in os.walk(rootdir):
            for file in files:
                # Construct the full file path by joining the subdirectory path and the file name
                full_file_path = os.path.join(subdir, file)

                if full_file_path.endswith(".yml") or full_file_path.endswith(".yaml"):
                    with open(full_file_path, "r") as rule_file:
                        rule_data = yaml.safe_load(rule_file)

                        if type(rule_data) == dict and "tags" in rule_data:
                            title = rule_data["title"]
                            tags = rule_data["tags"]

                            for tag in tags:
                                if re.match(r"attack.t[0-9.]*", tag):
                                    mapping.append({
                                        "usecase": title,
                                        "mitre": format_technique(tag),
                                        "source": "sigma"
                                })
    return mapping

def get_mapping_s1() -> list:
    """Fetch data from the S1QL repo: https://github.com/SentineLabs/S1QL-Queries

    Returns:
        list: the list of mapping with the format [{"usecase": usecase, "mitre": tag_mitre}]
    """
    mapping = []

    for rootdir in [
        "./S1QL-Queries/Queries"
    ]:

        # Use os.walk to iterate over the directory tree
        for subdir, dirs, files in os.walk(rootdir):
            for file in files:
                # Construct the full file path by joining the subdirectory path and the file name
                full_file_path = os.path.join(subdir, file)

                if full_file_path.endswith(".yml") or full_file_path.endswith(".yaml"):
                    with open(full_file_path, "r") as rule_file:
                        rule_data = yaml.safe_load(rule_file)

                        if type(rule_data) == dict and "tags" in rule_data:
                            title = rule_data["title"]
                            tags = rule_data["tags"]

                            for tag in tags:
                                if re.match(r"mitre.T[0-9.]*", tag):
                                    mapping.append({
                                        "usecase": title,
                                        "mitre": format_technique(tag.replace("mitre.", "")),
                                        "source": "s1ql"
                                    })

    return mapping
        
def get_mapping_sentinel() -> list:
    """Fetch rule and the associated mitre mapping from the Sentinel repo: https://github.com/Azure/Azure-Sentinel/tree/master

    Returns:
        list: the list of mapping with the format [{"usecase": usecase, "mitre": tag_mitre}]
    """
    mapping = []

    for rootdir in [
        "./Azure-Sentinel/Detections/",
        "./Azure-Sentinel/Hunting Queries/"
    ]:

        # Use os.walk to iterate over the directory tree
        for subdir, dirs, files in os.walk(rootdir):
            for file in files:
                # Construct the full file path by joining the subdirectory path and the file name
                full_file_path = os.path.join(subdir, file)

                if full_file_path.endswith(".yml") or full_file_path.endswith(".yaml"):
                    with open(full_file_path, "r") as rule_file:
                        rule_data = yaml.safe_load(rule_file)

                        if type(rule_data) == dict and "relevantTechniques" in rule_data:
                            title = rule_data["name"]
                            tags = rule_data["relevantTechniques"]
                            if tags and tags != [] and type(tags) == list:
                                for tag in tags:
                                    mapping.append({
                                            "usecase": title,
                                            "mitre": format_technique(tag),
                                            "source": "Sentinel"
                                        })
                            elif type(tags) == str and tags != "":
                                mapping.append({
                                        "usecase": title,
                                        "mitre": format_technique(tag),
                                        "source": "Setinel"
                                    })
    return mapping

def get_mapping_wazuh() -> list:
    """Fetch rules and the associated mitre technique from the Wazu repo and the SOCfortress wazuh detection rules repo: https://github.com/socfortress/Wazuh-Rules.git

    Returns:
        list: the list of mapping with the format [{"usecase": usecase, "mitre": tag_mitre}]
    """
    mapping = []
    
    rootdirs = ["wazuh/ruleset/rules", "Wazuh-Rules/"]
    
    for rootdir in rootdirs:
        # Use os.walk to iterate over the directory tree
        for subdir, dirs, files in os.walk(rootdir):
            for file in files:
                # Construct the full file path by joining the subdirectory path and the file name
                full_file_path = os.path.join(subdir, file)
                if full_file_path.endswith(".xml"):
                    
                    with open(full_file_path, "r") as rule_file:
                        try:
                            data = xmltodict.parse(rule_file.read())
                    
                        except :
                            print(f"error in file {full_file_path}")
                            
                        else:
                    
                            for rule in data['group']['rule']:
                                if "mitre" in rule and type(rule) == dict:
                                    if type(rule["mitre"]["id"]) == list:
                                        for tag in rule["mitre"]["id"]:
                                            if not tag.startswith("TA"):
                                                mapping.append({
                                                        "usecase": rule["description"],
                                                        "mitre": format_technique(tag),
                                                        "source": "Wazuh"
                                                    })
                                    elif type(rule["mitre"]["id"] == str):
                                        if not rule["mitre"]["id"].startswith("TA"):
                                            mapping.append({
                                                        "usecase": rule["description"],
                                                        "mitre": format_technique(rule["mitre"]["id"]),
                                                        "source": "Wazuh"
                                                    })
                                
    return mapping

def get_mapping_fortinet() -> list:
    """Fetch rule name and the associated mitre mapping from the Falcon friday repo: https://github.com/FalconForceTeam/FalconFriday

    Returns:
        list: the list of mapping with the format [{"usecase": usecase, "mitre": tag_mitre}]
    """
    mapping = []
    
    url = "https://help.fortinet.com/fsiem/Public_Resource_Access/7_1_2/rules/rule_descriptions.htm#rulesMitre"
    
    res = requests.get(url)
    
    tables = pd.read_html(res.text)
    for table in tables:

        table = table.drop("Tactic", axis=1 )
        table = table.drop("Severity", axis=1 )
            
        for record_dict in  table.to_dict(orient='records'):
            if not record_dict["Technique"] == "none":
                techniques = record_dict["Technique"].split(",")
                for technique in techniques:
                    mapping.append(
                        {
                            "usecase": record_dict["Name"],  
                            "mitre": format_technique(technique),
                            "source": "Fortinet"
                        }
                    )
            
    return mapping

def get_mapping_falconfriday() -> list:
    """Fetch data from the falconfriday repository

    Returns:
        list: the list of mapping with the format [{"usecase": usecase, "mitre": tag_mitre}]
    """
    mapping = []
    
    rootdir = "./FalconFriday/"
    
    # Use os.walk to iterate over the directory tree
    for subdir, dirs, files in os.walk(rootdir):
        for file in files:
            is_first_line = True
            # Construct the full file path by joining the subdirectory path and the file name
            full_file_path = os.path.join(subdir, file)
            if full_file_path.endswith(".md"):
                with open(full_file_path, "r") as rule_file:
                    for line in rule_file.readlines():
                        if is_first_line:
                            is_first_line = False
                            title = line.replace("\n", "").replace("# ", "")
                        matchs = re.findall(r"T[0-9]{4}", line)
                        if matchs != []:
                            for tag in matchs:
                                title = re.sub(r"T[0-9]{4} - ", "", title)
                                title = re.sub(r"T[0-9]{4}.[0-9]{3} - ", "", title)
                                mapping.append({
                                    "usecase": title,
                                    "mitre": format_technique(tag),
                                    "source": "falcon"
                                })
                            
                                
    return mapping

def build_data_set(stats = False) -> list:
    mapping = []
    
    sentinel = get_mapping_sentinel()
    sigma = get_mapping_sigma()
    wazuh = get_mapping_wazuh()
    fortinet = get_mapping_fortinet()
    s1ql = get_mapping_s1()
    falcon = get_mapping_falconfriday()
    
    mapping.extend(sentinel)
    mapping.extend(sigma)
    mapping.extend(wazuh)
    mapping.extend(fortinet)    
    mapping.extend(s1ql)
    mapping.extend(falcon)
    
    if stats:
        print(f"""
            Dataset build, with the following ruleset:
            Sigma: {len(sigma)} rules
            Sentinel: {len(sentinel)} rules
            Wazuh: {len(wazuh)} rules
            Fortinet: {len(fortinet)} rules
            S1QL: {len(s1ql)} rules
            Falcon: {len(falcon)} rules
            """)
        
    keys = mapping[0].keys()

    with open('mapping.csv', 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(mapping)
        
    return mapping

def map_usecase_title(usecases: list, stats = False):
    # Load your CSV data
    data = pd.read_csv('mapping.csv')

    # Split the data into features (X) and target (y)
    X = data['usecase']
    y = data['mitre']

    # Split the data into training and validation sets
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.1, random_state=42)

    # Convert text data into numerical features
    vectorizer = TfidfVectorizer()
    X_train_transformed = vectorizer.fit_transform(X_train)
    X_val_transformed = vectorizer.transform(X_val)

    # Train the model
    model = GaussianNB()
    model.fit(X_train_transformed.toarray(), y_train)
    
    y_val_pred = model.predict(X_val_transformed.toarray())
    precision = precision_score(y_val, y_val_pred, average='macro',zero_division=0)
        
    # Recall
    recall = recall_score(y_val, y_val_pred, average='micro')
    
    # F1 Score
    f1 = f1_score(y_val, y_val_pred, average='weighted')
    
    # Score
    score = model.score(X_val_transformed.toarray(), y_val)
    
    if stats:
        print(f"""
            Model evaluation
            Precision: {precision}
            Recall: {recall}
            F1: {f1}
            Score: {score}
            """)
    
    # Make predictions
    new_rule_names_transformed = vectorizer.transform(usecases)

    predictions = model.predict(new_rule_names_transformed.toarray())    
    probas = model.predict_proba(new_rule_names_transformed.toarray())
    
    return predictions

def main():
    args = parser.parse_args()
    
    if args.build:
        print("Building dataset")
        build_data_set(args.stats)
    
    usecases = [args.title]
    predictions = map_usecase_title(usecases, args.stats)

    for i in range(len(predictions)):
        if args.link:
            print(f"https://attack.mitre.org/techniques/{predictions[i].upper()}") 
        else:
            print(predictions[i].upper())
        
    return predictions
    
        
if __name__ == "__main__":
    main()
    