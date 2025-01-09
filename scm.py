#!/usr/bin/env python3

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
        base_params["sa_id"] = data["sa_id"]
        base_params["sa_pass"] = data["sa_pass"]
        base_params["auth_url"] = data["auth_url"]


def getAuthToken():
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "client_credentials",
        "scope": "tsg_id:{}".format(base_params["tsg_id"])
    }
    response = requests.post(base_params["auth_url"], headers=headers, auth=(base_params["sa_id"], base_params["sa_pass"]), data=data)
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


def main():
    readConfiguration()
    token = getAuthToken()
    getDevices(token)


if __name__ == '__main__':
    sys.exit(main())
