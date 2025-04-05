#!/usr/bin/env python3

import argparse
import json
import os
import requests
import sys


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
        base_params["tsg_id"] = data["tsg_id"]
        base_params["client_id"] = data["client_id"]
        base_params["client_secret"] = data["client_secret"]
        base_params["auth_url"] = data["auth_url"]
        base_params["region"] = data["region"]


def getAuthToken():
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "client_credentials",
        "scope": "tsg_id:{}".format(base_params["tsg_id"])
    }
    # print(base_params)
    auth = (base_params["client_id"], base_params["client_secret"])
    response = requests.post(base_params["auth_url"], headers=headers, auth=auth, data=data)
    if response.status_code!=200:
        raise Exception("auth result code: {} - {}".format(response.status_code, response.text))
    response_json = json.loads(response.text)
    return response_json["access_token"]


def getDevices(token):
    keys = [
        "display_name",
        "folder",
        "is_connected",
        "last_disconnect_time",
        "software_version",
    ]
    url = "https://api.strata.paloaltonetworks.com/config/setup/v1/devices"
    headers = {
        "Authorization": "Bearer {}".format(token)
    }
    response_json = json.loads(requests.get(url, headers=headers).text)
    for entry in response_json["data"]:
        print()
        print("{} {} {}".format(entry["id"], entry["hostname"], entry["model"]))
        for k in keys:
          print("  {:21}:   {}".format(k, entry[k]))
        #print(json.dumps(entry, indent=4))


def scmGetRequest(token, path, params):
    url = f"https://api.strata.paloaltonetworks.com/{path}"
    headers = {
        "Authorization": "Bearer {}".format(token)
    }
    return json.loads(requests.get(url, headers=headers, params=params).text)


def scmDeleteRequest(token, path):
    url = f"https://api.strata.paloaltonetworks.com/{path}"
    headers = {
        "Authorization": "Bearer {}".format(token)
    }
    return json.loads(requests.delete(url, headers=headers).text)


def scmPostRequest(token, path, data):
    url = f"https://api.strata.paloaltonetworks.com/{path}"
    headers = {
        "Authorization": "Bearer {}".format(token),
        "X-PANW-Region": base_params['region']
    }
    response = requests.post(url, headers=headers, json=data)
    # print("URL")
    # print(response.request.url)
    # print("Body")
    # print(response.request.body)
    # print("Headers")
    # print(response.request.headers)
    # print("text")
    # print(response.text)
    return json.loads(response.text)


def getServiceConnections(token):
    path = "config/deployment/v1/service-connections"
    params = {}
    rj = scmGetRequest(token, path, params)

    for j in rj['data']:
        print(j['id'])
        path = f"config/deployment/v1/service-connections/{j['id']}"
        params = {}
        rj = scmGetRequest(token, path, params)
        print(json.dumps(rj, indent=4))



def getServiceConnectionsInsights(token):
    path = "insights/v3.0/resource/query/sites/sc_list"
    data = {
        "filter": {
            "operator": "AND",
            "rules": [
                {
                    "property": "event_time",
                    "operator": "last_n_hours",
                    "values": [
                        1
                    ]
                },
            ]
        }
    }
    rj = scmPostRequest(token, path, data)
    # print(json.dumps(rj, indent=4))
    data = {}
    for sc in rj['data']:
        data[sc['site_name']] = {
            "source_ip": sc['source_ip'],
            "site_state_name": sc['site_state_name'],
            "bgp_site_state_name": sc['bgp_site_state_name'],
        }
    return data


def printServiceConnectionsInsights():
    token = getAuthToken()
    jd = getServiceConnectionsInsights(token)
    for sc,scv in jd.items():
        print(f"{sc:20} {scv['source_ip']} {scv['site_state_name']} {scv['bgp_site_state_name']}")





def main():
    readConfiguration()

    parser = argparse.ArgumentParser(
        description='useful actions on panorama'
    )
    # parser.add_argument('--all', action='store_true')
    parser.add_argument('--name', nargs='?', action='store')
    parser.add_argument('cmd')
    args = parser.parse_args()

    if args.cmd == "get-devices":
        token = getAuthToken()
        getDevices(token)
        sys.exit(0)

    if args.cmd == "get-service-connections":
        printServiceConnectionsInsights()
        sys.exit(0)

    print(f"Unknown command {args.cmd}")

if __name__ == '__main__':
    sys.exit(main())
