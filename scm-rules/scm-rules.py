#!/usr/bin/env python3 

import argparse
import json
import os
import yaml

from scm.client import Scm
import scm.exceptions


base_params = {}

def readConfiguration(scm_creds_file=None):
    if scm_creds_file:
        pcf = scm_creds_file
    else:
        if os.path.isfile("scm_creds.json"):
            pcf = os.path.join("scm_creds.json")
        else:
            pcf = os.path.join(os.path.expanduser("~"), "scm_creds.json")
    with open(pcf) as f:
        data = json.load(f)
        base_params["tsg_id"]   = data["tsg_id"]
        base_params["sa_id"]    = data["sa_id"]
        base_params["sa_pass"]  = data["sa_pass"]
        base_params["auth_url"] = data["auth_url"]
        base_params["region"]   = data["region"]




def readRules(file):
    with open(file) as f:
        return yaml.safe_load(f)




def assembleRule(folder, parameters):
    rule = {
        "folder": folder,
        "name": parameters.get('name'),
        "from_": parameters.get('from', ["any"]),
        "to_": parameters.get('to', ["any"]),
        "source": parameters.get('source'),
        "destination": parameters.get('destination'),
        "application": parameters.get('application', ["any"]),
        "service": parameters.get('service', ["application-default"]),
        "action": parameters.get('action'),
        "category": parameters.get('category', "any"),
        "source_user": parameters.get('source_user', "any"),
    }
    return rule




def buildRules(rules):
    complete_rules = {}
    for folder in rules:
        print(folder)
        complete_rules[folder] = {}
        for rt in ['pre', 'post']:
            complete_rules[folder][rt] = []
            if rt in rules[folder]:
                for r in rules[folder][rt]:
                    print(r.get('name'))
                    rule = assembleRule(folder, r)
                    complete_rules[folder][rt].append(rule)
    return complete_rules



def applyRules(client, rules):
    for folder in rules:
        print(folder)
        for rt in ['pre', 'post']:
            if rt in rules[folder]:
                for r in rules[folder][rt]:
                    name = r.get('name')
                    try:
                        client.security_rule.create(r, rulebase=rt)
                    except scm.exceptions.NameNotUniqueError:
                        print(f"Rule {name} already exists")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', nargs='?', action='store')
    args = parser.parse_args()

    readConfiguration()
    rules_from_file = readRules(args.file)
    complete_rules = buildRules(rules_from_file)
    print(complete_rules)

    client = Scm(
        client_id=base_params['sa_id'],
        client_secret=base_params['sa_pass'],
        tsg_id=base_params['tsg_id']
    )
    applyRules(client, complete_rules)

