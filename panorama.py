#!env python3
import argparse
import base64
import copy
import json
from lxml import etree
from lxml.builder import E
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
pano_base_url = 'https://{}/api/'.format('dummy')

class commitFailed(Exception):
    pass

def readConfiguration():
    global pano_base_url
    with open("/Users/rweglarz/prog/ce-common/panorama_creds.json") as f:
        data = json.load(f)
        base_params["key"] = data["api_key"]
        pano_base_url = 'https://{}/api/'.format(data['hostname'])


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


def commitDevices(entries):
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


def getDevices(dg=None, connected=None):
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
            if connected == True and dev_connected == "no":
                continue
            if connected == False and dev_connected == "yes":
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
        d = getDevices(connected=True)
        print(d)
        j = commitDevices(d)
        print("Devices commit job: {}".format(j))
        waitForJobToFinish(j)
        sys.exit(0)
    print("Unrecognized command")
    sys.exit(1)


if __name__ == '__main__':
    sys.exit(main())
