#!env python3
import argparse
import base64
import copy
import json
from lxml import etree
from lxml.builder import E
import os
import requests
import re
import sys
import time

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

base_params = {
    'key': '',
    'type': 'op',
}
base_config = {}
pano_base_url = 'https://{}/api/'.format('dummy')

class commitFailed(Exception):
    pass


def readConfiguration():
    global pano_base_url
    global base_config

    with open(os.path.join(os.path.expanduser("~"), "panorama_creds.json")) as f:
        data = json.load(f)
        base_params["key"] = data["api_key"]
        pano_base_url = 'https://{}/api/'.format(data['hostname'])
    with open(os.path.join(os.path.expanduser("~"), "panorama_config.json")) as f:
        base_config = json.load(f)


def panoramaCommit():
    params = copy.copy(base_params)
    params['type'] = 'commit'
    r = etree.Element('commit')
    params['cmd'] = etree.tostring(r)
    resp = requests.get(pano_base_url, params=params, verify=False).content
    xml_resp = etree.fromstring(resp)
    if not xml_resp.attrib.get('status') == 'success':
        print(resp)
        raise Exception("Failed to submit commit")
    msg = xml_resp.find('.//msg').text
    if msg == "There are no changes to commit.":
        print(msg)
        return None
    job = xml_resp.find('.//job').text
    return job


def getJobStatus(id):
    params = copy.copy(base_params)
    r = etree.Element('show')
    s = etree.SubElement(r, 'jobs')
    s = etree.SubElement(s, 'id')
    s.text = str(id)
    params['cmd'] = etree.tostring(r)
    resp = requests.get(pano_base_url, params=params, verify=False).content
    xml_resp = etree.fromstring(resp)
    #print(etree.tostring(xml_resp, pretty_print=True).decode())
    return xml_resp


def waitForJobToFinish(id):
    if id == None:
        print("Job is none")
        return
    while True:
        js = getJobStatus(id)
        s = js.find('./result/job/status').text
        if s == "FIN":
            break
        time.sleep(5)
    result = js.find('./result/job/result').text
    if result == "OK":
        print("Job: {} result: {}".format(id, result))
        return
    print(etree.tostring(js, pretty_print=True).decode())
    for d in js.findall('./result/job/devices/entry'):
        dn = d.find('./devicename').text
        sn = d.find('./serial-no').text
        r = d.find('./result').text
        det_msg = ""
        print("== {}/{} - {} - {}".format(dn, sn, r, det_msg))
        for l in d.findall('./details/msg/errors/line'):
            print(l.text)
    raise commitFailed("")


def queryLogs(log_type, query):
    params = copy.copy(base_params)
    params['type'] = 'log'
    params['log-type'] = log_type
    params['dir'] = 'backward'
    params['query'] = query
    resp = etree.fromstring(
        requests.get(pano_base_url, params=params, verify=False).content)
    #print(etree.tostring(resp, pretty_print=True).decode())
    job = resp.find('.//job').text
    while True:
        params = copy.copy(base_params)
        params['type'] = 'log'
        params['action'] = 'get'
        params['job-id'] = job
        resp = etree.fromstring(
            requests.get(pano_base_url, params=params, verify=False).content)
        status = resp.find('./result/job/status').text
        #print('log job {} status {}'.format(job, status))
        # just to note the active job status
        if status=='ACT':
            continue
        if status=='FIN':
            break
        raise Exception("Unknown job status: {}, query: {}".format(status, query))
    return resp.find('./result/log/logs')


def isDeviceCandidateForRemovalBasedOnHistory(logs, min_time):
    now = datetime.datetime.now()
    newest = None
    oldest = None
    for i_l in logs.findall('./entry'):
        time_gen = i_l.find('time_generated').text
        time_gen_ts = datetime.datetime.strptime(time_gen, '%Y/%m/%d %H:%M:%S')
        log = i_l.find('opaque').text
        print("{} {}".format(time_gen_ts, log))
        oldest = time_gen_ts
        if newest==None:
            newest = time_gen_ts
            if not re.match(r'disconnected', log):
                assert("Device should be disconnected, but most recent log is: ".format(log))
    time_diff = (now-newest).total_seconds() / 60
    if (time_diff > min_time):
        return True
    return False


def commitDevices(entries):
    if len(entries) == 0:
        print("No devices to commit")
        return None
    params = copy.copy(base_params)
    params['type'] = 'commit'
    params['action'] = 'all'
    r = etree.Element('commit-all')
    sp = etree.SubElement(r, 'shared-policy')
    it = etree.SubElement(sp, 'include-template')
    it.text = "yes"
    dgs = etree.SubElement(sp, 'device-group')
    for dg in entries:
        dge = etree.SubElement(dgs, 'entry', name=dg)
        des = etree.SubElement(dge, 'devices')
        for s in entries[dg]:
            se = etree.SubElement(des, 'entry', name=s)
    params['cmd'] = etree.tostring(r)
    print(params['cmd'])
    resp = requests.get(pano_base_url, params=params, verify=False).content
    xml_resp = etree.fromstring(resp)
    if not xml_resp.attrib.get('status') == 'success':
        print(resp)
        raise Exception("Failed submit commit")
    msg = xml_resp.find('.//msg').text
    if msg == "There are no changes to commit.":
        print(msg)
        return None
    job = xml_resp.find('.//job').text
    return job


def getDGOfDevice(serial):
    params = copy.copy(base_params)
    r = etree.Element('show')
    s = etree.SubElement(r, 'devicegroups')
    params['cmd'] = etree.tostring(r)
    dgs = etree.fromstring(
        requests.get(pano_base_url, params=params, verify=False).content)
    r = {}
    for i_dg in dgs.findall('./result/devicegroups/entry'):
        dg_name = i_dg.get('name')
        for i_dev in i_dg.findall('./devices/entry'):
            if serial == i_dev.find('serial').text:
                return dg_name
    return None


def getDevices(dg=None, ts=None, connected=None, in_sync=None):
    params = copy.copy(base_params)
    r = etree.Element('show')
    s = etree.SubElement(r, 'template-stack')
    params['cmd'] = etree.tostring(r)
    tss = etree.fromstring(
        requests.get(pano_base_url, params=params, verify=False).content)
    ts_out_of_sync = []
    for i_ts in tss.findall('./result/template-stack/entry'):
        ts_name = i_ts.get('name')
        if ts and ts_name != ts:
            continue
        for i_dev in i_ts.findall('./devices/entry'):
            serial = i_dev.find('serial').text
            dev_connected = i_dev.find('connected').text
            template_status = i_dev.find('template-status').text
            if connected == True and dev_connected == "no":
                continue
            if connected == False and dev_connected == "yes":
                continue
            if in_sync == True and template_status == "Out of Sync":
                continue
            if in_sync == False and template_status == "In Sync":
                continue
            ts_out_of_sync.append(serial)

    params = copy.copy(base_params)
    r = etree.Element('show')
    s = etree.SubElement(r, 'devicegroups')
    params['cmd'] = etree.tostring(r)
    dgs = etree.fromstring(
        requests.get(pano_base_url, params=params, verify=False).content)
    r = {}
    for i_dg in dgs.findall('./result/devicegroups/entry'):
        dg_name = i_dg.get('name')
        if dg and dg_name != dg:
            continue
        for i_dev in i_dg.findall('./devices/entry'):
            serial = i_dev.find('serial').text
            dev_connected = i_dev.find('connected').text
            policy_status = i_dev.find('shared-policy-status').text
            if connected == True and dev_connected == "no":
                continue
            if connected == False and dev_connected == "yes":
                continue
            if in_sync == True and (policy_status == "Out of Sync" or serial in ts_out_of_sync):
                continue
            if in_sync == False and (policy_status == "In Sync" and not serial in ts_out_of_sync):
                continue
            print('{} {}'.format(dg_name, serial))
            if not dg_name in r:
                r[dg_name] = []
            r[dg_name].append(serial)
    return r


def main():
    parser = argparse.ArgumentParser(
        description='useful actions on panorama'
    )
    #parser.add_argument('--clean', action='store_true')
    parser.add_argument('cmd')
    args = parser.parse_args()

    readConfiguration()
    print(args.cmd)
    if args.cmd=="commit":
        j = panoramaCommit()
        print("Panorama commit job: {}".format(j))
        waitForJobToFinish(j)
        sys.exit(0)
    if args.cmd=="commit-all":
        j = panoramaCommit()
        print("Panorama commit job: {}".format(j))
        waitForJobToFinish(j)
        d = getDevices(connected=True, in_sync=False)
        print(d)
        j = commitDevices(d)
        print("Devices commit job: {}".format(j))
        waitForJobToFinish(j)
        sys.exit(0)
    if args.cmd=="push-all":
        d = getDevices(connected=True)
        print(d)
        j = commitDevices(d)
        print("Devices commit job: {}".format(j))
        try:
            waitForJobToFinish(j)
        except commitFailed:
            sys.exit(1)
        else:
            sys.exit(0)
    print("Unrecognized command")
    sys.exit(1)


if __name__ == '__main__':
    sys.exit(main())
