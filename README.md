# An AI that map use cases name with Mitre Att&CK techniques

## Set up

1. Clone all repository listed in [Acknowledgments](#acknowledgments)
2. Install requirements.txt

## Examples: 
![ex.png](./docs/ex.png)

## Theory

### Single Class Classification
> Supposed that one rules name can only have one mitre technnique

GaussianNB
```            
Precision: 0.5455894095627782
Recall: 0.6323763955342903
F1: 0.6389246074030653
```

SVC
```            
Model evaluation
Precision: 0.5357550854252018
Recall: 0.7121212121212122
F1: 0.695978132355355
```

ComplementNB
```            
Model evaluation
Precision: 0.4482258623309422
Recall: 0.6363636363636364
F1: 0.5980927305198915
```

MultinomialNB
```            
Model evaluation
Precision: 0.18923977334201353
Recall: 0.46331738437001596
F1: 0.3851311586787331
```


BernoulliNB
```           
Model evaluation
Precision: 0.07316943930209778
Recall: 0.3373205741626794
F1: 0.2439527660736201
```

### Multiple Label Classficiation (MLC) & Multiple Class Classification (MCC)
> Supposed that one rules name can have multiles mitre technnique

Thoses models give a mutch better accuracy
For MCC, the avrage accuracy for a technique is over 0.9 but this if because of the large number of techniques compared to the number of 
rules mapped in thoses techniques.
 
To test the dataset I try focussing only on the Mitre technique (MCC), see branche MLC
Precissions:
```
Accuracy for Privilege_Escalation is 0.8424543946932007
Accuracy for Defense_Evasion is 0.8308457711442786
Accuracy for Impact is 0.956882255389718
Accuracy for Discovery is 0.9436152570480929
Accuracy for Persistence is 0.8606965174129353
Accuracy for Resource_Development is 0.9850746268656716
Accuracy for Reconnaissance is 0.9950248756218906
Accuracy for Collection is 0.9502487562189055
Accuracy for Initial_Access is 0.8938640132669984
Accuracy for Execution is 0.8772802653399668
Accuracy for Credential_Access is 0.9038142620232172
Accuracy for Lateral_Movement is 0.9552238805970149
Accuracy for Command_and_Control is 0.9336650082918739
Accuracy for Exfiltration is 0.988391376451078
```

However it almost never map uses cases titles to a mitre tactic.

Multiples improvement for the dataset exist:
- More exemples of mapping for each use case
- Using the same Mitre ATT&CK versions
- Make sure that all sources uses the same technique for the same uses cases

## Acknowledgments
Sources of the trained dataset came from:
- https://github.com/SentineLabs/S1QL-Queries
- https://github.com/Azure/Azure-Sentinel/tree/master
- https://github.com/socfortress/Wazuh-Rules
- https://github.com/FalconForceTeam/FalconFriday?tab=BSD-3-Clause-1-ov-file#readme
- https://github.com/wazuh/wazuh/?tab=License-1-ov-file#readme
- https://help.fortinet.com/fsiem/Public_Resource_Access/7_1_2/rules/rule_descriptions.htm#rulesMitre
- Mitre Att&CK: https://attack.mitre.org/techniques

Others:
- Choice of the models: https://scikit-learn.org/stable/tutorial/machine_learning_map/index.html
- https://medium.com/analytics-vidhya/an-introduction-to-multi-label-text-classification-b1bcb7c7364c