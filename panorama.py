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


def panorama_commit():
    params = copy.copy(base_params)
    params['type'] = 'commit'
    r = etree.Element('commit')
    params['cmd'] = etree.tostring(r)
    resp = requests.get(pano_base_url, params=params, verify=False).content
    xml_resp = etree.fromstring(resp)
    if not xml_resp.attrib.get('status') == 'success':
        print("Failed submit commit")
        print(resp)
        return False
    msg = xml_resp.find('.//msg').text
    if msg == "There are no changes to commit.":
        print(msg)
        return True
    job = xml_resp.find('.//job').text
    print('job id: {}'.format(job))
    return True


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
