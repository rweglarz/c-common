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
        base_params["tsg_id"]         = data["tsg_id"]
        base_params["client_id"]      = data["client_id"]
        base_params["client_secret"] = data["client_secret"]
        # base_params["auth_url"]        = data["auth_url"]
        # base_params["region"]          = data.get("region", "americas")




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
        print(f"building rule content for folder: {folder}")
        complete_rules[folder] = {}
        for rt in ['pre', 'post']:
            complete_rules[folder][rt] = []
            if rt in rules[folder]:
                for r in rules[folder][rt]:
                    # print(r.get('name'))
                    rule = assembleRule(folder, r)
                    complete_rules[folder][rt].append(rule)
    return complete_rules



def compareRuleExistenceInFolder(required_rules, existing_rules):
    required_rules_names = [r.get('name') for r in required_rules]
    existing_rules_names = [r.name for r in existing_rules]
    rules_to_create = []
    rules_to_delete = []
    for rule_name in required_rules_names:
        if rule_name not in existing_rules_names:
            rules_to_create.append(rule_name)

    for rule_name in existing_rules_names:
        if rule_name not in required_rules_names:
            rules_to_delete.append(rule_name)
    return (rules_to_create, rules_to_delete)



def planRuleMoves(required_rules, existing_rules):
    rule_ids = {}
    for r in existing_rules:
        rule_ids[r.name] = r.id
    required_rules_names = [r.get('name') for r in required_rules]
    existing_rules_names = [r.name for r in existing_rules]

    operations = []
    for (idx, rule_name) in enumerate(required_rules_names):
        ex_idx = existing_rules_names.index(rule_name)
        if idx==ex_idx:
            print(f"  Rule {rule_name} in correct position")
            continue
        print(f"  Move {rule_name} from {ex_idx=} to {idx=}")
        if idx==0:
            operations.append({
                "rule_id": rule_ids[rule_name],
                "destination": "top",
                "destination_rule": None,
            })
        else:
            operations.append({
                "rule_id": rule_ids[rule_name],
                "destination": "before",
                "destination_rule": rule_ids[existing_rules_names[idx]]
            })
        existing_rules_names.pop(ex_idx)
        existing_rules_names.insert(idx, rule_name)
    return operations



def applyRuleSetToSCMFolder(folder, complete_rules):
    client = Scm(
        client_id=base_params['client_id'],
        client_secret=base_params['client_secret'],
        tsg_id=base_params['tsg_id']
    )
    required_rules = complete_rules[folder][rt]
    existing_rules = client.security_rule.list(folder=folder, rulebase=rt, exact_match=True)
    (rules_to_create, rules_to_delete) = compareRuleExistenceInFolder(required_rules, existing_rules)
    print(f" {rules_to_create=}")
    print(f" {rules_to_delete=}")

    required_rules_names = [r.get('name') for r in required_rules]
    existing_rules_names = [r.name for r in existing_rules]
    modified_ruleset = False

    print(" Creating...")
    for r in rules_to_create:
        idx = required_rules_names.index(r)
        rule = required_rules[idx]
        print(f"  create {r=}")
        client.security_rule.create(rule, rulebase=rt)
        modified_ruleset = True
    print(" Deleting...")
    for r in rules_to_delete:
        idx = existing_rules_names.index(r)
        id = existing_rules[idx].id
        print(f"  delete {r=} {id=}")
        client.security_rule.delete(id, rulebase=rt)
        modified_ruleset = True

    if modified_ruleset:
        print("Refreshing rules")
        existing_rules = client.security_rule.list(folder=folder, rulebase=rt, exact_match=True)

    print(" Rule order check...")
    moves = planRuleMoves(required_rules, existing_rules)
    for move in moves:
        rule_id = move['rule_id']
        move_target = {
            "destination": move['destination'],
            "destination_rule": move['destination_rule'],
            "rulebase": rt
        }
        client.security_rule.move(rule_id, move_target)



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', nargs='?', action='store')
    args = parser.parse_args()

    if os.getenv("SCM_CLIENT_ID") is not None:
        base_params['client_id']     = os.getenv("SCM_CLIENT_ID")
        base_params['client_secret'] = os.getenv("SCM_CLIENT_SECRET")
        base_params['tsg_id']        = os.getenv("SCM_TSG_ID")
    else:
        readConfiguration()
    if not all([base_params['client_id'], base_params['client_secret'], base_params['tsg_id']]):
        print("Incomplete configuration")
        exit(1)

    print(f"Using file {args.file}")
    rules_from_file = readRules(args.file)
    complete_rules = buildRules(rules_from_file)

    for folder in rules_from_file:
        for rt in ['pre', 'post']:
            print(f"Handling {folder} {rt}")
            applyRuleSetToSCMFolder(folder, complete_rules)

