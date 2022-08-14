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
    args = parser.parse_args()

    readConfiguration()
    panorama_commit()


if __name__ == '__main__':
    sys.exit(main())
