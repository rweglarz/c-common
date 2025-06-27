#!/usr/bin/env python3

import argparse
import json
import logging
import os
import requests
import sys
import time

from scm.client import Scm
from scm.exceptions import (
    APIError,
    AuthenticationError,
    BadRequestError,
    InvalidObjectError,
    NotFoundError,
    ObjectNotPresentError,
    ServerError,
)


COMMIT_ALL_MAX_CHECK_COUNT = 90
MAX_ONE_TASK_RETRY = 5

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
        base_params["tsg_v2"] = data.get("tsg_v2", False)


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
    region = None
    connectors = None
    connector_groups = None
    logger = None
    tsg_v2 = None
    sse_base_path = "/sse/connector/v2.0/api"

    def __init__(self, **kwargs):
        self.region = kwargs.pop("region")
        self.tsg_v2 = kwargs.pop("tsg_v2")
        super().__init__(**kwargs)
        if self.tsg_v2:
            self.sse_base_path = "/sse/connector/2/v2.0/api"
        self.logger = logging.getLogger(__name__)

    def _addRegionHeader(self, **kwargs):
        assert(self.region)
        region_header = {
            "X-PANW-Region": self.region
        }
        kwargs["headers"] = kwargs.get("headers", {}) | region_header
        return kwargs

    def deleteSSE(self, **kwargs):
        kwargs = self._addRegionHeader(**kwargs)
        return self.delete(**kwargs)

    def getSSE(self, **kwargs):
        kwargs = self._addRegionHeader(**kwargs)
        return self.get(**kwargs)

    def postSSE(self, **kwargs):
        kwargs = self._addRegionHeader(**kwargs)
        return self.post(**kwargs)

    def putSSE(self, **kwargs):
        kwargs = self._addRegionHeader(**kwargs)
        return self.put(**kwargs)

    def commit(self, folders, description):
        if len(folders)==0:
            folders = ["All"]
        try:
            result = super().commit(folders=folders, description=description, sync=False)
        except InvalidObjectError as e:
            self.logger.error(f"Invalid commit parameters: {e.message}")
            return None
        except Exception as e:
            self.logger.error(f"Invalid commit: {e.message}")
            self.logger.error(f"message: {e.details['message']}")
            return None
        else:
            return result.job_id

    def commitAll(self, folders, description):
        path = "/config/operations/v1/config-versions/candidate:push"
        if len(folders)==0:
            folders = ["All"]
        data = {
            "folders": folders,
            "description": description,
        }
        try:
            r = self.post(endpoint=path, json=data)
        except BadRequestError as e:
            self.logger.error(f"Commit attempt failed - BadRequestError")
            self.logger.error(e)
            return None
        if r["success"]!=True:
            self.logger.error(f"Commit attempt failed - {r}")
            return None
        return r["job_id"]

    def refreshZTNAConnectors(self):
        path = f"{self.sse_base_path}/connectors"
        connectors = self.getSSE(endpoint=path)["data"]
        self.connectors = {}
        for c in connectors:
            self.connectors[c["name"]] = c

    def refreshZTNAConnectorGroups(self):
        path = f"{self.sse_base_path}/connector-groups"
        connector_groups = self.getSSE(endpoint=path)["data"]
        self.connector_groups = {}
        for cg in connector_groups:
            self.connector_groups[cg["name"]] = cg

    def refreshZTNAApplications(self):
        path = f"{self.sse_base_path}/applications"
        applications = self.getSSE(endpoint=path)["data"]
        self.applications= {}
        for app in applications:
            self.applications[app["name"]] = app
    
    def createZTNAApplication(self, fqdn, group_id, port="80"):
        path = f"{self.sse_base_path}/applications"
        data = {
            "name": fqdn,
            "group": group_id,
            "icmp_allowed": True,
            "app_enabled": True,
            "spec": [{
                "fqdn": fqdn,
                "tcp_port": port,
                "probe_port": port,
                "probe_type": "tcp_ping",
                "udp_port": "",
            }]
        }
        r = self.postSSE(endpoint=path, json=data)
        return r["oid"]

    def updateZTNAApplication(self, oid, fqdn, group_id, port="80"):
        path = f"{self.sse_base_path}/applications/{oid}"
        data = {
            "name": fqdn,
            "group": group_id,
            "icmp_allowed": True,
            "app_enabled": True,
            "spec": [{
                "fqdn": fqdn,
                "tcp_port": port,
                "probe_port": port,
                "probe_type": "tcp_ping",
                "udp_port": "",
            }]
        }
        r = self.putSSE(endpoint=path, json=data)
        return r["oid"]
    
    def deleteZTNAApplication(self, object_id):
        path = f"{self.sse_base_path}/applications/{object_id}"
        r = self.deleteSSE(endpoint=path)
        self.logger.debug(r)

    def deleteZTNAConnector(self, object_id):
        path = f"{self.sse_base_path}/connectors/{object_id}"
        r = self.deleteSSE(endpoint=path)
        self.logger.debug(r)

    def deleteZTNAConnectorGroup(self, object_id):
        path = f"{self.sse_base_path}/connector-groups/{object_id}"
        r = self.deleteSSE(endpoint=path)
        self.logger.debug(r)

    def createZTNAConnector(self, name, group_id):
        path = f"{self.sse_base_path}/connectors"
        data = {
            "name": name,
            "group": group_id,
        }
        r = self.postSSE(endpoint=path, json=data)
        return r["oid"]

    def createZTNAConnectorGroup(self, name, description):
        path = f"{self.sse_base_path}/connector-groups"
        data = {
            "name": name,
            "is_autoscale": False,
            "description": description,
        }
        r = self.postSSE(endpoint=path, json=data)
        return r["oid"]

    def waitForJobAndChildTasks(self, primary_job_id):
        jobs_status = {}
        check_number = 0
        only_one_task_retry_count = 0
        for check_number in range(0, COMMIT_ALL_MAX_CHECK_COUNT):
            recent_jobs = scm_client.list_jobs(limit=200)
            for j in recent_jobs.data:
                if j.parent_id==primary_job_id or j.id==primary_job_id:
                    if j.id not in jobs_status:
                        jobs_status[j.id] = {}
                    jobs_status[j.id]['js'] = j
                    jobs_status[j.id]['last_seen'] = check_number
            if len(jobs_status)==0:
                print(f"Job {primary_job_id} not found")
                sys.exit(1)
            s = ""
            pending_tasks_count = 0
            failed_tasks_count = 0
            status_strings = []
            for j in jobs_status.values():
                jid = j['js'].id
                # if the job is not in the last 200, fetch it individually
                if j['last_seen']!=check_number:
                    jsv = scm_client.get_job_status(jid)
                    jobs_status[jid]['js'] = jsv.data[0]
                status_strings.append(f"{jid} {j['js'].result_str}")
                if j['js'].result_str=="PEND":
                    pending_tasks_count += 1
                if j['js'].result_str=="FAIL":
                    failed_tasks_count += 1
            s = ", ".join(status_strings)
            completed_count = len(jobs_status)-pending_tasks_count
            if failed_tasks_count>0:
                fail_str = f"FAIL:{failed_tasks_count} "
            else:
                fail_str = ""
            print(f"{fail_str}OK:{completed_count} /{len(jobs_status)} -- jobs: {s}")
            if pending_tasks_count==0:
                if completed_count>1:
                    break
                # only one completed, we might not have child jobs yet
                only_one_task_retry_count+= 1
                if only_one_task_retry_count > MAX_ONE_TASK_RETRY:
                    print(f"Max single job retry reached, aborting")
                    break
                if jobs_status[primary_job_id]['js'].type_str != "CommitAndPush":
                    break
            time.sleep(45)
        else:
            print(f"Reached max check count ${COMMIT_ALL_MAX_CHECK_COUNT}")
            return 1
        if failed_tasks_count==0:
            print("No Pending tasks, all completed OK")
            return 0
        print("No Pending tasks, some tasks FAILED")
        return 1



def main():
    if os.getenv("SCM_CLIENT_ID") is not None:
        base_params['client_id']     = os.getenv("SCM_CLIENT_ID")
        base_params['client_secret'] = os.getenv("SCM_CLIENT_SECRET")
        base_params['tsg_id']        = os.getenv("SCM_TSG_ID")
        base_params['region']        = os.getenv("PA_REGION")
        base_params['tsg_v2']        = os.getenv("SCM_TSG_V2", False)
    else:
        readConfiguration()

    parser = argparse.ArgumentParser(
        description='useful actions on scm'
    )
    # parser.add_argument('--all', action='store_true')
    parser.add_argument('--job', nargs='?', action='store')
    parser.add_argument('--name', nargs='?', action='store')
    parser.add_argument('--format', nargs='?', action='store')
    parser.add_argument('--rn', action='store_true')
    parser.add_argument('--mu', action='store_true')
    parser.add_argument('--folders', nargs='?', action='store')
    parser.add_argument('--all-admins', action='store_true')
    parser.add_argument('cmd')
    args = parser.parse_args()

    global scm_client
    scm_client = MScm(
        client_id=base_params["client_id"],
        client_secret=base_params["client_secret"],
        tsg_id=base_params["tsg_id"],
        region=base_params["region"],
        tsg_v2=base_params["tsg_v2"],
    )

    if args.cmd == "get-devices":
        token = getAuthToken()
        getDevices(token)
        sys.exit(0)

    if args.cmd == "get-prisma-access-connections":
        printPrismaAccessConnections(format=args.format)
        sys.exit(0)

    folders = []
    if args.folders:
        for f in args.folders.split(","):
            folders.append(f)
    if args.rn:
        folders.append("Remote Networks")
    if args.mu:
        folders.append("Mobile Users")

    if args.cmd in ["commit", "commit-and-wait"]:
        # specific folders (if provided)
        if args.all_admins:
            job_id = scm_client.commitAll(folders, "api commit all-admins")
        else:
            job_id = scm_client.commit(folders, "api commit one-admin")
        if not job_id:
            sys.exit(1)
        if args.cmd == "commit-and-wait":
            print(f"Parent job id: {job_id}")
            rv = scm_client.waitForJobAndChildTasks(job_id)
            sys.exit(rv)
        else:
            print(job_id)
            sys.exit(0)

    if args.cmd in ["commit-all", "commit-all-and-wait"]:
        # all forders, all admins
        job_id = scm_client.commitAll(["All"], "api commit all--all-admins")
        if not job_id:
            sys.exit(1)
        if args.cmd == "commit-all-and-wait":
            rv = scm_client.waitForJobAndChildTasks(job_id)
            sys.exit(rv)
        else:
            print(job_id)
            sys.exit(0)

    print(f"Unknown command {args.cmd}")
    sys.exit(1)

if __name__ == '__main__':
    sys.exit(main())
