#!/usr/bin/env python3

import argparse
import json
import os
import requests
import sys
import time

from scm.client import Scm
from scm.exceptions import (
   InvalidObjectError,
   NotFoundError,
   AuthenticationError,
   ServerError
)



base_params = {}
scm_client = None


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



def getPrismaAccessConnectionsInsights(connection_type):
    assert(connection_type in ["sc", "rn"])
    headers = {
        "X-PANW-Region": base_params['region']
    }
    path = f"/insights/v3.0/resource/query/sites/{connection_type}_list"
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
    rj = scm_client.post(endpoint=path, headers=headers, json=data)
    data = {}
    for conn in rj['data']:
        data[conn['site_name']] = {
            "source_ip": conn.get('source_ip', 'Unknown'),
            "site_state_name": conn.get('site_state_name'),
            "bgp_site_state_name": conn.get('bgp_site_state_name'),
        }
    return data


def getPrismaAccessConnections():
    jd = {}
    jd['remote_networks'] = getPrismaAccessConnectionsInsights("rn")
    jd['service_connections'] = getPrismaAccessConnectionsInsights("sc")
    return jd

def printPrismaAccessConnections(format="terminal"):
    assert(format in ["json", "terminal"])
    pac = getPrismaAccessConnections()
    if format=="terminal":
        print("Remote networks")
        for conn,connv in pac['remote_networks'].items():
            print(f"{conn:20} {connv['source_ip']:16} {connv['site_state_name']:6} {connv['bgp_site_state_name']}")
        print("Service connections")
        for conn,connv in pac['service_connections'].items():
            print(f"{conn:20} {connv['source_ip']:16} {connv['site_state_name']:6} {connv['bgp_site_state_name']}")
        return
    if format=="json":
        jo = {
            "rn_public_ips": {},
            "sc_public_ips": {}
        }
        for conn,connv in pac['remote_networks'].items():
            if connv['source_ip']=="Unknown":
                continue
            jo['rn_public_ips'][conn] = connv['source_ip']
        for conn,connv in pac['service_connections'].items():
            if connv['source_ip']=="Unknown":
                continue
            jo['sc_public_ips'][conn] = connv['source_ip']
        print(json.dumps(jo, indent=1))





class MScm(Scm):
    # def __init__(self, length):
    #     super().__init__(length, length)
    def aa(self, something):
        pass

    def commitAll(self, description):
        try:
            result = self.commit(folders=["All"], description=description, sync=False)
        except InvalidObjectError as e:
            print(f"Invalid commit parameters: {e.message}")
        except Exception as e:
            print(result)
            print(f"Invalid commit: {e.message}")
        return result.job_id
    
    def waitForJobAndChildTasks(self, primary_job_id):
        jobs_status = {}
        while True:
            recent_jobs = scm_client.list_jobs(limit=100)
            for j in recent_jobs.data:
                if j.parent_id==primary_job_id or j.id==primary_job_id:
                    jobs_status[j.id] = j
            for j in jobs_status.values():
                print(f"{j.id} {j.result_str}")
            time.sleep(30)


def main():
    readConfiguration()

    parser = argparse.ArgumentParser(
        description='useful actions on panorama'
    )
    # parser.add_argument('--all', action='store_true')
    parser.add_argument('--job', nargs='?', action='store')
    parser.add_argument('--name', nargs='?', action='store')
    parser.add_argument('--format', nargs='?', action='store')
    parser.add_argument('cmd')
    args = parser.parse_args()

    global scm_client
    scm_client = MScm(
        client_id=base_params["client_id"],
        client_secret=base_params["client_secret"],
        tsg_id=base_params["tsg_id"]
    )

    if args.cmd == "get-devices":
        token = getAuthToken()
        getDevices(token)
        sys.exit(0)

    if args.cmd == "get-prisma-access-connections":
        printPrismaAccessConnections(format=args.format)
        sys.exit(0)

    if args.cmd == "commit-all-and-wait":
        job_id = scm_client.commitAll("api commit")
        print(f"Parent job id: {job_id}")
        scm_client.waitForJobAndChildTasks(job_id)
        sys.exit(0)

    if args.cmd == "wait-for-job":
        scm_client.waitForJobAndChildTasks(args.job)
        sys.exit(0)

    print(f"Unknown command {args.cmd}")

if __name__ == '__main__':
    sys.exit(main())
