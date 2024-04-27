import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report

from pprint import pprint
import yaml
import xmltodict
import os
import csv
import re
import requests

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
                                        "mitre": tag.split(".")[1],
                                        "source": "sigma"
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
                                            "mitre": tag.split(".")[0].lower(),
                                            "source": "Sentinel"
                                        })
                            elif type(tags) == str and tags != "":
                                mapping.append({
                                        "usecase": title,
                                        "mitre": tags.split(".")[0].lower(),
                                        "source": "Setinel"
                                    })
    return mapping

def get_mapping_wazuh() -> list:
    """Fetch rules and the associated mitre technique from the Wazu repo: 

    Returns:
        list: the list of mapping with the format [{"usecase": usecase, "mitre": tag_mitre}]
    """
    mapping = []
    
    rootdir = "wazuh/ruleset/rules"
    
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
                            if "mitre" in rule:
                                if type(rule["mitre"]["id"]) == list:
                                    for tag in rule["mitre"]["id"]:
                                        if not tag.startswith("TA"):
                                            mapping.append({
                                                    "usecase": rule["description"],
                                                    "mitre": tag.split(".")[0].lower(),
                                                    "source": "Wazuh"
                                                })
                                elif type(rule["mitre"]["id"] == str):
                                    if not rule["mitre"]["id"].startswith("TA"):
                                        mapping.append({
                                                    "usecase": rule["description"],
                                                    "mitre": rule["mitre"]["id"].split(".")[0].lower(),
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
                            "mitre": technique.split(".")[0].lower(),
                            "source": "Fortinet"
                        }
                    )
            
    return mapping

def set_mapping() -> list:
    mapping = []
    
    sentinel = get_mapping_sentinel()
    sigma = get_mapping_sigma()
    wazuh = get_mapping_wazuh()
    fortinet = get_mapping_fortinet()
    
    mapping.extend(sentinel)
    mapping.extend(sigma)
    mapping.extend(wazuh)
    mapping.extend(fortinet)    
    
    print(f"""
          Sigma: {len(sigma)}
          Sentinel: {len(sentinel)}
          Wazuh: {len(wazuh)}
          Fortinet: {len(fortinet)}
          """)
        
    keys = mapping[0].keys()

    with open('mapping.csv', 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(mapping)
        
    return mapping

def map_use_case(usecase):
    # Load your CSV data
    data = pd.read_csv('mapping.csv')

    # Split the data into features (X) and target (y)
    X = data['usecase']
    y = data['mitre']

    # Split the data into training and validation sets
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    # Convert text data into numerical features
    vectorizer = TfidfVectorizer()
    X_train_transformed = vectorizer.fit_transform(X_train)
    X_val_transformed = vectorizer.transform(X_val)

    # Train the model
    model = MultinomialNB()
    model.fit(X_train_transformed, y_train)

    # Evaluate the model
    y_val_pred = model.predict(X_val_transformed)

    new_rule_names_transformed = vectorizer.transform(usecase)

    predictions = model.predict(new_rule_names_transformed)
    
    return predictions


def main():

    usecases = [
        "Petitpotam detected",
        "User added to sensible admin group"
    ]
    
    mapping = map_use_case(usecases)
    
    for i in range(len(mapping)):
        print(f"{usecases[i]} -> {mapping[i]}")
        
        
if __name__ == "__main__":
    #set_mapping()
    main()
    
