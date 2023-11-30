#!env python3
import argparse
import base64
import copy
import datetime
import json
from lxml import etree
from lxml.builder import E
import operator
import os
import requests
import re
import ssl
import sys
from tabulate import tabulate
import time
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

base_params = {
    'key': '',
    'type': 'op',
}
base_config = {}
pano_base_url = 'https://{}/api/'.format('dummy')
panoramaRequestGet = None
panoramaRequestPost = None

class commitFailed(Exception):
    pass

class jobNotFound(Exception):
    pass


def readConfiguration(panorama_creds_file=None):
    global pano_base_url
    global base_config

    if panorama_creds_file:
        pcf = panorama_creds_file
    else:
        if os.path.isfile("panorama_creds.json"):
            pcf = os.path.join("panorama_creds.json")
        else:
            pcf = os.path.join(os.path.expanduser("~"), "panorama_creds.json")
    with open(pcf) as f:
        data = json.load(f)
        base_params["key"] = data["api_key"]
        pano_base_url = 'https://{}/api/'.format(data['hostname'])
    print("Using =  {}  = from  {}".format(data["name"], pcf))
    with open(os.path.join(os.path.expanduser("~"), "panorama_config.json")) as f:
        base_config = json.load(f)


class CustomHttpAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = urllib3.poolmanager.PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, ssl_context=self.ssl_context)


def getLegacySSLRequestsSession():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = False
    # ctx.verify_mode = ssl.CERT_NONE
    ctx.options |= 0x4  # OP_LEGACY_SERVER_CONNECT
    #ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT in 3.12?
    session = requests.session()
    session.mount('https://', CustomHttpAdapter(ctx))
    return session

class panoramaRequest:
    rs = None
    verify = True
    def __init__(self, verify=True):
        self.verify = verify
        if self.verify:
            self.rs = requests.session()
        else:
            # SSLError(SSLError(1, '[SSL: UNSAFE_LEGACY_RENEGOTIATION_DISABLED] unsafe legacy renegotiation disabled 
            self.rs = getLegacySSLRequestsSession()

    def get(self, params):
        c = self.rs.get(pano_base_url, params=params, verify=self.verify).content
        return c

    def post(self, params, files):
        c = self.rs.post(pano_base_url, params=params, files=files, verify=self.verify).content
        return c


def panoramaCommit():
    params = copy.copy(base_params)
    params['type'] = 'commit'
    r = etree.Element('commit')
    params['cmd'] = etree.tostring(r)
    resp = panoramaRequestGet(params)
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
    resp = panoramaRequestGet(params)
    try:
        xml_resp = etree.fromstring(resp)
    except:
        print("Failed response:")
        print(resp)
        raise Exception("Failed parsing resp for job id:".format(id))
    #print(etree.tostring(xml_resp, pretty_print=True).decode())
    return xml_resp


def waitForJobToFinish(id):
    safe_to_ignore_warnings = [
        r'In virtual-router \w+, BGP export policy only_local_prefixes is enabled but not used by any peer-group'
    ]
    safe_to_ignore_errors = [
        r'Autogenerated SDWAN configuration',
        r'Configuration committed successfully',
        r'Panorama connectivity check was successful for .*',
        r'Performing panorama connectivity check .attempt 1 of 1.',
    ]
    if id == None:
        print("Job is none")
        return
    while True:
        js = getJobStatus(id)
        if js.attrib.get('code') == '7':
            for l in js.findall('./msg/line'):
                if re.match(r'job \d+ not found', l.text):
                    raise jobNotFound("")
            raise Exception("unknown error")
        s = js.find('./result/job/status').text
        if s == "FIN":
            break
        time.sleep(5)
    result = js.find('./result/job/result').text
    if result == "OK":
        print("Job: {} result: {}".format(id, result))
    for d in js.findall('./result/job/devices/entry'):
        dn = d.find('./devicename').text
        sn = d.find('./serial-no').text
        r = d.find('./result').text
        det_msg = ""
        print("== {} / {} - {} - {}".format(dn, sn, r, det_msg))
        warnings = []
        ignored = 0
        for l in d.findall('./details/msg/warnings/line'):
            for sti in safe_to_ignore_warnings:
                if re.match(sti, l.text):
                    ignored+= 1
                    break
            else:
                warnings.append(l.text)
        print("\tWarnings left:{} (and ignored: {})".format(len(warnings), ignored))
        for l in warnings:
            print("\t\t{}".format(l))
        errors = []
        ignored = 0
        for l in d.findall('./details/msg/errors/line'):
            for sti in safe_to_ignore_errors:
                if re.match(sti, l.text):
                    ignored+= 1
                    break
            else:
                errors.append(l.text)
        print("\tErrors left:{} (and ignored: {})".format(len(errors), ignored))
        for l in errors:
            print("\t\t{}".format(l))
    if result != "OK":
        print(etree.tostring(js, pretty_print=True).decode())
        raise commitFailed("")


def queryLogs(log_type, query):
    params = copy.copy(base_params)
    params['type'] = 'log'
    params['log-type'] = log_type
    params['dir'] = 'backward'
    params['query'] = query
    resp = etree.fromstring(panoramaRequestGet(params))
    #print(etree.tostring(resp, pretty_print=True).decode())
    job = resp.find('.//job').text
    while True:
        params = copy.copy(base_params)
        params['type'] = 'log'
        params['action'] = 'get'
        params['job-id'] = job
        resp = etree.fromstring(panoramaRequestGet(params))
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
    for i_l in logs.findall('./entry'):
        time_gen = i_l.find('time_generated').text
        time_gen_ts = datetime.datetime.strptime(time_gen, '%Y/%m/%d %H:%M:%S')
        log = i_l.find('opaque').text
        print("{} {}".format(time_gen_ts, log))
        if newest==None:
            newest = time_gen_ts
            if not re.match(r'.*disconnected.*', log):
                raise Exception("Device should be disconnected, but most recent log is: {}".format(log))
    time_diff = (now-newest).total_seconds() / 60
    if (time_diff > min_time):
        return True
    return False


def doAPIDeleteFromConfig(params, xpath):
    resp = etree.fromstring(panoramaRequestGet(params))
    rtxt = etree.tostring(resp).decode()
    if not resp.attrib.get('status') == 'success':
        print(etree.tostring(resp, pretty_print=True).decode())
        raise Exception("Delete operation did not succeed: {} {}".format(xpath, rtxt))
    if resp.attrib.get('code') == '20':
        # success, command succeeded
        msg = resp.find('msg').text
        if msg=="command succeeded":
            return True
    if resp.attrib.get('code') == '7':
        msg = resp.find('msg').text
        if msg=="Object doesn't exist":
            return False
        if msg=="No object to delete in delete handler":
            #this can happen when dg was deleted, show device group still shows the list 
            return True
    raise Exception("Unknown response for delete operation: {} {}".format(xpath, rtxt))


def testXMLAESubinterface():
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'get'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/template/entry[@name='{}']/config/devices".format("apitest")
    xpath+= "/entry[@name='localhost.localdomain']/network/interface"
    xpath+= "/aggregate-ethernet/entry[@name='{}']".format("ae1")
    params['xpath'] = xpath
    resp = etree.fromstring(panoramaRequestGet(params))
    print(etree.tostring(resp, pretty_print=True).decode())
    rtxt = etree.tostring(resp).decode()

    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'set'
    xpath+= "/layer3/units"
    params['xpath'] = xpath
    r = etree.Element('entry')
    r.attrib["name"] = "ae1.20"
    ips = etree.SubElement(r, 'ip')
    ip = etree.SubElement(ips, 'entry')
    ip.attrib["name"] = "2.2.2.20/32"
    tag = etree.SubElement(r, 'tag')
    tag.text = "20"
    params['element'] = etree.tostring(r)
    resp = etree.fromstring(panoramaRequestGet(params))
    print(etree.tostring(resp, pretty_print=True).decode())
    return


def deleteDeviceFromDG(serial, dg):
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'delete'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/device-group/entry[@name='{}']/devices/entry[@name='{}']".format(dg, serial)
    params['xpath'] = xpath
    r = doAPIDeleteFromConfig(params, xpath)
    print("{} {}removed from dg {}".format(serial, "" if r else "not ", dg))
    return r


def deleteDeviceFromTS(serial, ts):
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'delete'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/template-stack/entry[@name='{}']/devices/entry[@name='{}']".format(ts, serial)
    params['xpath'] = xpath
    r = doAPIDeleteFromConfig(params, xpath)
    print("{} {}removed from ts {}".format(serial, "" if r else "not ", ts))
    return r


def deleteDeviceFromLCG(serial, lcg):
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'delete'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/log-collector-group/entry[@name='{}']/logfwd-setting/devices/entry[@name='{}']".format(lcg, serial)
    params['xpath'] = xpath
    r = doAPIDeleteFromConfig(params, xpath)
    print("{} {}removed from lcg {}".format(serial, "" if r else "not ", lcg))
    return r


def deleteDeviceFromPanoramaDevices(serial):
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'delete'
    xpath = "/config/mgt-config/devices/entry[@name='{}']".format(serial)
    params['xpath'] = xpath
    r = doAPIDeleteFromConfig(params, xpath)
    print("{} {}removed from panorama device list".format(serial, "" if r else "not "))
    return r


def enableAutoContentPushOnTS(ts):
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'set'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/template-stack/entry[@name='{}']".format(ts)
    params['xpath'] = xpath
    r = etree.Element('auto-push-on-1st-conn')
    r.text = "yes"
    params['element'] = etree.tostring(r)
    resp = etree.fromstring(panoramaRequestGet(params))
    rtxt = etree.tostring(resp).decode()
    if not resp.attrib.get('status') == 'success':
        print(resp)
        raise Exception("Config operation did not succeed: {} {}".format(xpath, rtxt))
    if resp.attrib.get('code') == '20':
        # success, command succeeded
        msg = resp.find('msg').text
        if msg=="command succeeded":
            return True
    raise Exception("Unknown response for config operation: {} {}".format(xpath, rtxt))


def enableAutoContentPush():
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'get'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/template-stack"
    params['xpath'] = xpath

    tss = etree.fromstring(panoramaRequestGet(params))
    for i_ts in tss.findall('./result/template-stack/entry'):
        ts_name = i_ts.get('name')
        desc_n = i_ts.find('description')
        if desc_n is None:
            continue
        if not 'pat:acp' in desc_n.text:
            continue
        auto_push_n = i_ts.find('auto-push-on-1st-conn')
        if auto_push_n is not None and auto_push_n.text=="yes":
            continue
        print("Enabling auto content push on: {}".format(ts_name))
        enableAutoContentPushOnTS(ts_name)


def cleanupDevices(min_time, stable_dgs, todo_dg=None, todo_serial=None):
    delicense_jobs = []
    params = copy.copy(base_params)
    r = etree.Element('show')
    s = etree.SubElement(r, 'devices')
    s = etree.SubElement(s, 'all')
    params['cmd'] = etree.tostring(r)
    resp = etree.fromstring(panoramaRequestGet(params))
    lic_devs = getSupportPortalLicensedDevices(None)
    for i_d in resp.findall('./result/devices/entry'):
        serial = i_d.find('serial').text
        connected = i_d.find('connected').text
        print()
        print("== {}".format(serial))
        if todo_serial is not None and todo_serial!=serial:
            print("Not a match by serial".format(serial))
            continue
        if todo_serial is None and connected=="yes":
            print("Not suitable for delete {}, still connected".format(serial))
            continue
        dg = getDGOfDevice(serial)
        if dg in stable_dgs:
            print("Do not delete {} based on dg {} membership".format(serial, dg))
            continue
        if todo_dg is not None and dg!=todo_dg:
            print("Do not delete {} different dg {}".format(serial, dg))
            continue
        if todo_dg is None and todo_serial is None:
            query = "(description contains '{} connected')".format(serial)
            query+= "or (description contains '{} disconnected') ".format(serial)
            query+= "or (description contains 'successfully authenticated for bootstrapped device {}') ".format(serial)
            logs = queryLogs('system', query)
            if not isDeviceCandidateForRemovalBasedOnHistory(logs, min_time):
                print("Not suitable for delete {}, too fresh".format(serial))
                continue
        if serial in lic_devs:
            print("Needs to be delicensed first {}".format(lic_devs[serial]))
            job = delicenseFirewallFromPanorama(serial)
            delicense_jobs.append(job)
            continue
        ts = getTSOfDeviceFromConfig(serial)
        lcg = getLCGOfDevice(serial)
        print("Will delete {}, dg: {}, ts: {}, lcg: {}".format(serial, dg, ts, lcg))
        if dg:
            deleteDeviceFromDG(serial, dg)
        if ts:
            deleteDeviceFromTS(serial, ts)
        if lcg:
            deleteDeviceFromLCG(serial, lcg)
        deleteDeviceFromPanoramaDevices(serial)
    return delicense_jobs


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
    resp = panoramaRequestGet(params)
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


def commitLCG(lcg):
    params = copy.copy(base_params)
    params['type'] = 'commit'
    params['action'] = 'all'
    er = etree.Element('commit-all')
    elcc = etree.SubElement(er, 'log-collector-config')
    elcg = etree.SubElement(elcc, 'log-collector-group')
    elcg.text = lcg
    params['cmd'] = etree.tostring(er)
    resp = etree.fromstring(panoramaRequestGet(params))
    xml_resp = etree.fromstring(resp)
    if not xml_resp.attrib.get('status') == 'success':
        print(resp)
        raise Exception("Failed submit commit")
    msg = xml_resp.find('.//msg')
    for l in msg.findall('./line'):
        print(l.text)
    return None


def getDGOfDevice(serial):
    if not hasattr(getDGOfDevice, "dgs"):
        params = copy.copy(base_params)
        r = etree.Element('show')
        s = etree.SubElement(r, 'devicegroups')
        params['cmd'] = etree.tostring(r)
        getDGOfDevice.dgs = etree.fromstring(panoramaRequestGet(params=params))
    dgs = getDGOfDevice.dgs
    r = {}
    for i_dg in dgs.findall('./result/devicegroups/entry'):
        dg_name = i_dg.get('name')
        for i_dev in i_dg.findall('./devices/entry'):
            if serial == i_dev.find('serial').text:
                return dg_name
    return None


def getTSOfDevice(serial):
    if not hasattr(getTSOfDevice, "tss"):
        params = copy.copy(base_params)
        r = etree.Element('show')
        s = etree.SubElement(r, 'template-stack')
        params['cmd'] = etree.tostring(r)
        getTSOfDevice.tss =etree.fromstring(panoramaRequestGet(params))
    tss = getTSOfDevice.tss
    for i_ts in tss.findall('./result/template-stack/entry'):
        ts_name = i_ts.get('name')
        for i_dev in i_ts.findall('./devices/entry'):
            if serial == i_dev.find('serial').text:
                return ts_name
    return None


def getTSOfDeviceFromConfig(serial):
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'get'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/template-stack"
    params['xpath'] = xpath
    tss = etree.fromstring(panoramaRequestGet(params))
    for i_ts in tss.findall('./result/template-stack/entry'):
        ts_name = i_ts.get('name')
        for i_dev in i_ts.findall('./devices/entry'):
            s = i_dev.get('name')
            if s==serial:
                return ts_name
    return None


def getLCGOfDevice(serial):
    if not hasattr(getLCGOfDevice, "lcgs"):
        params = copy.copy(base_params)
        r = etree.Element('show')
        s = etree.SubElement(r, 'log-collector-group')
        s = etree.SubElement(s, 'all')
        params['cmd'] = etree.tostring(r)
        getLCGOfDevice.lcgs =  etree.fromstring(panoramaRequestGet(params=params))
    #print(etree.tostring(lcgs, pretty_print=True).decode())
    lcgs = getLCGOfDevice.lcgs
    for i_lcg in lcgs.findall('./result/log-collector-group/entry'):
        lcg_name = i_lcg.get('name')
        for i_dev in i_lcg.findall('./device-list/entry'):
            if serial == i_dev.get('name'):
                return lcg_name
    return None

def getLoggingStatusOfDevice(serial):
    if not hasattr(getLoggingStatusOfDevice, "ls"):
        params = copy.copy(base_params)
        r = etree.Element('show')
        s = etree.SubElement(r, 'logging-status')
        s = etree.SubElement(s, 'all')
        params['cmd'] = etree.tostring(r)
        #getLoggingStatusOfDevice.ls = etree.fromstring(
        #    requests.get(pano_base_url, params=params, verify=False).content)
        getLoggingStatusOfDevice.ls = panoramaRequestGet(params=params)
    ls = getLoggingStatusOfDevice.ls
    for l in ls.splitlines():
        if "{}-log-collection".format(serial) in l.decode():
            return True
    return False

def getDevices():
    params = copy.copy(base_params)
    qr = etree.Element('show')
    qd = etree.SubElement(qr, 'devices')
    qs = etree.SubElement(qd, 'all')
    params['cmd'] = etree.tostring(qr)
    xdevs = etree.fromstring(panoramaRequestGet(params))
    #print(etree.tostring(xdevs, pretty_print=True).decode())
    devs = {}
    for i_d in xdevs.findall('./result/devices/entry'):
        serial = i_d.find('serial').text
        devs[serial] = {}
        d = devs[serial]
        for e in ['connected', 'dg', 'ha', 'hostname', 'ip', 'logging-status', 'sw-version', 'ts']:
            d[e] = '-'
        d['serial'] = serial
        try:
            # manually added devices which never connected to panorama will not have these details
            d['ip'] = i_d.find('ip-address').text
            d['hostname'] = i_d.find('hostname').text
            d['sw-version']= i_d.find('sw-version').text
            d['ha']= i_d.find('ha/state').text
        except:
            pass
        dg = getDGOfDevice(serial)
        ts = getTSOfDevice(serial)
        if i_d.find('connected').text == "yes":
            d['connected'] = 'yes'
        if getLoggingStatusOfDevice(serial) is True:
            d['logging-status'] = 'yes'
        if dg is not None:
            d['dg'] = dg
        if ts is not None:
            d['ts'] = ts
    return devs

def printDevices():
    devs = getDevices()
    headers = [
        'hostname',
        'ip',
        'serial',
        'dg',
        'ts',
        'connected',
        'logging',
        'sw',
        'ha',
    ]
    tdevs = []
    for d in devs.values():
        tdevs.append([
            d['hostname'],
            d['ip'],
            d['serial'],
            d['dg'],
            d['ts'],
            d['connected'],
            d['logging-status'],
            d['sw-version'],
            d['ha'],
        ])
    print(tabulate(sorted(tdevs, key=operator.itemgetter(2)), headers=headers))


def getDevicesForCommit(dg=None, ts=None, connected=None, in_sync=None):
    params = copy.copy(base_params)
    r = etree.Element('show')
    s = etree.SubElement(r, 'template-stack')
    params['cmd'] = etree.tostring(r)
    tss = etree.fromstring(panoramaRequestGet(params))
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
    dgs = etree.fromstring(panoramaRequestGet(params=params))
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
            #print('{} {}'.format(dg_name, serial))
            if not dg_name in r:
                r[dg_name] = []
            r[dg_name].append(serial)
    return r

def getSupportPortalLicensedDevices(authcode):
    url = "https://api.paloaltonetworks.com/api/license/get"
    api_key = base_config["license"]["api_key"]
    if authcode is None:
        authcode = base_config["license"]["authcode"]
    headers = {
        "apikey": api_key
    }
    data = {
        "authcode": authcode
    }
    devices = {}
    resp = requests.post(url, data=data, headers=headers, verify=False)
    if resp.status_code!=200:
        print(resp)
        raise Exception("Invalid response: code:{}, {}".format(resp.status_code, resp.content))
    devs = json.loads(resp.content)
    for d in devs['UsedDeviceDetails']:
        sn = d.get('SerialNumber')
        devices[sn] = d
    return devices

def delicenseFirewallFromPanorama(serial):
    # request batch license deactivate VM-Capacity devices 007957000352464 mode auto
    params = copy.copy(base_params)
    r = etree.Element('request')
    s = etree.SubElement(r, 'batch')
    s = etree.SubElement(s, 'license')
    s = etree.SubElement(s, 'deactivate')
    v = etree.SubElement(s, 'VM-Capacity')
    s = etree.SubElement(v, 'devices')
    s.text = serial
    s = etree.SubElement(v, 'mode')
    s.text = 'auto'
    params['cmd'] = etree.tostring(r)
    resp = panoramaRequestGet(params)
    xml_resp = etree.fromstring(resp)
    if not xml_resp.attrib.get('status') == 'success':
        print(resp)
        raise Exception("Failed to request delicense for {}".format(serial))
    job = xml_resp.find('.//job').text
    print("Delicense job {} triggered for {}".format(job, serial))
    return job

def ipTagMapping(op, serial, ip, tag):
    assert(op in ['register', 'unregister'])
    assert(ip is not None)
    params = copy.copy(base_params)
    um = etree.Element('uid-message')
    t = etree.SubElement(um, 'type')
    t.text = 'update'
    p = etree.SubElement(um, 'payload')
    o = etree.SubElement(p, op)
    e = etree.SubElement(o, 'entry')
    e.attrib['ip'] = ip
    t = etree.SubElement(e, 'tag')
    m = etree.SubElement(t, 'member')
    m.attrib['timeout'] = str(12*3600)
    m.attrib['persistent'] = "0"
    m.text = tag
    # print(etree.tostring(um, pretty_print=True).decode())
    params['type'] = 'user-id'
    if serial is not None:
        params['target'] = serial
    files = { 'file': ('file', etree.tostring(um), 'text/xml')}
    resp = panoramaRequestPost(params, files)
    # print(resp.request.headers)
    # print(resp.request.url)
    # print(resp.request.body)
    # print(resp.content)
    xml_resp = etree.fromstring(resp)
    # print(etree.tostring(xml_resp, pretty_print=True).decode())
    if not xml_resp.attrib.get('status') == 'success':
        print(resp)
        raise Exception(
            "Ip-tag operation did not succeed: {}".format(resp))

def getIPTagMapping(serial=None, tag='all'):
    iptag = {}
    params = copy.copy(base_params)
    r = etree.Element('show')
    s = etree.SubElement(r, 'object')
    s = etree.SubElement(s, 'registered-ip')
    s = etree.SubElement(s, tag)
    params['cmd'] = etree.tostring(r)
    if serial is not None:
        params['target'] = serial
    resp = panoramaRequestGet(params)
    try:
        xml_resp = etree.fromstring(resp)
    except:
        raise Exception("Failed parsing resp for registered-ip: ".format(resp))
    if not xml_resp.attrib.get('status') == 'success':
        raise Exception("Operation failed: {}".format(resp))
    for e in xml_resp.findall('./result/entry'):
        ip = e.get('ip')
        iptag[ip] = []
        for t in e.findall('./tag/member'):
            iptag[ip].append(t.text)
    return iptag


def submitConfigChange(params):
    resp = etree.fromstring(panoramaRequestGet(params))
    rtxt = etree.tostring(resp).decode()
    if not resp.attrib.get('status') == 'success':
        print(resp)
        raise Exception(
            "Config operation did not succeed: {} {}".format(params['xpath'], rtxt))
    if resp.attrib.get('code') == '20':
        # success, command succeeded
        msg = resp.find('msg').text
        if msg == "command succeeded":
            return True
    raise Exception(
        "Unknown response for config operation: {} {}".format(params['xpath'], rtxt))


def buildVWANDeviceConfig(dev_root, props):
    es = etree.SubElement(dev_root, 'entry')
    es.attrib['name'] = props['serial']
    ebgp = etree.SubElement(es, 'bgp')
    e = etree.SubElement(ebgp, 'router-id')
    e.text = props['router_id']
    e = etree.SubElement(ebgp, 'loopback-address')
    e.text = props['router_id']
    e = etree.SubElement(ebgp, 'as-number')
    e.text = props['asn']
    e = etree.SubElement(es, 'vr-name')
    e.text = props['vr']
    e = etree.SubElement(es, 'type')
    e.text = props['type']
    e = etree.SubElement(es, 'site')
    e.text = props['site']
    if 'prefixes' in props:
        epr = etree.SubElement(ebgp, 'prefix-redistribute')
        for pfx in props['prefixes']:
            e = etree.SubElement(epr, 'entry')
            e.attrib['name'] = pfx
    if 'public_ips' in props:
        eis = etree.SubElement(es, 'interfaces')
        for iif in props['public_ips']:
            e = etree.SubElement(eis, 'entry')
            e.attrib['name'] = iif
            e = etree.SubElement(e, 'nat-config')
            e = etree.SubElement(e, 'static')
            e = etree.SubElement(e, 'public-ip')
            e.text = props['public_ips'][iif]


def configureVWAN():
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'set'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath += "/plugins/sd_wan"
    params['xpath'] = xpath
    devs = {}
    # devices
    dr = etree.Element('devices')
    for d in devs.values():
        buildVWANDeviceConfig(dr, d)
    params['element'] = etree.tostring(dr)
    print(etree.tostring(dr, pretty_print=True).decode())
    submitConfigChange(params)

    # cluster
    cr = etree.Element('vpn-cluster')
    ec = etree.SubElement(cr, 'entry')
    ec.attrib['name'] = "azure-vwan"
    ect = etree.SubElement(ec, 'type')
    ect.text = 'hub-spoke'
    eb = etree.SubElement(ec, 'branches')
    for d in devs.values():
        print(d)
        if d['type'] != 'branch':
            continue
        e = etree.SubElement(eb, 'entry')
        e.attrib['name'] = d['serial']
    ehs = etree.SubElement(ec, 'hubs')
    for d in devs.values():
        if d['type'] != 'hub':
            continue
        eh = etree.SubElement(ehs, 'entry')
        eh.attrib['name'] = d['serial']
        e = etree.SubElement(eh, 'allow-dia-vpn-failover')
        e.text = 'no'
        e = etree.SubElement(eh, 'priority')
        e.text = str(d['prio'])
    print(etree.tostring(cr, pretty_print=True).decode())
    params['element'] = etree.tostring(cr)
    submitConfigChange(params)


class AzureClient:
    compute_client  = None
    network_client  = None
    resource_client = None
    rg_names        = []
    subscription_id = None

    def __init__(self, subscription_id, owner_tag_value):
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.resource import ResourceManagementClient
        self.subscription_id = subscription_id
        credential = DefaultAzureCredential()
        self.compute_client = ComputeManagementClient(credential, self.subscription_id)
        self.network_client = NetworkManagementClient(credential, self.subscription_id)
        self.resource_client = ResourceManagementClient(credential, self.subscription_id)
        for rgi in self.resource_client.resource_groups.list(filter="tagName eq 'owner' and tagValue eq '{}'".format(owner_tag_value)):
            self.rg_names.append(rgi.name)

    def findVMIDByName(self, vm_name):
        for rgi in self.rg_names:
            vms_in_rg = self.compute_client.virtual_machines.list(rgi)
            for vmi in vms_in_rg:
                if vm_name==vmi.name:
                    return vmi.id
        return None

    def getAllVMs(self):
        vm_ids = []
        for rgi in self.rg_names:
            vms_in_rg = self.compute_client.virtual_machines.list(rgi)
            for vmi in vms_in_rg:
                vm_ids.append(vmi.id)
        return vm_ids

    def getVMIPs(self, vm_id):
        ips = {}
        vm_name = vm_id.split('/')[-1]
        rg_name = vm_id.split('/')[4]
        vm = self.compute_client.virtual_machines.get(rg_name, vm_name)
        for nii in vm.network_profile.network_interfaces:
            nic_name = nii.id.split('/')[-1]
            nic = self.network_client.network_interfaces.get(rg_name, nic_name)
            ip_configs = {}
            for ipci in nic.ip_configurations:
                ip_configs[ipci.name] = {}
                if ipci.public_ip_address:
                    public_ip_name = ipci.public_ip_address.id.split('/')[-1]
                    ip_configs[ipci.name]['public_ip_address'] = self.network_client.public_ip_addresses.get(rg_name, public_ip_name).ip_address
                ip_configs[ipci.name]['private_ip_address'] = ipci.private_ip_address
            ips[nic_name] = ip_configs
        return ips


def main():
    parser = argparse.ArgumentParser(
        description='useful actions on panorama'
    )
    #parser.add_argument('--clean', action='store_true')
    parser.add_argument('--panorama-creds-file', nargs='?', action='store')
    parser.add_argument('--serial', nargs='?', action='store')
    parser.add_argument('--ip', nargs='?', action='store')
    parser.add_argument('--device-group', nargs='?', action='store')
    parser.add_argument('--not-on-panorama', action='store_true')
    parser.add_argument('--query', nargs='?', action='store')
    parser.add_argument('cmd')
    args = parser.parse_args()

    readConfiguration(panorama_creds_file=args.panorama_creds_file)
    print(args.cmd)

    pr = panoramaRequest(verify=False)
    global panoramaRequestGet
    panoramaRequestGet = pr.get
    global panoramaRequestPost
    panoramaRequestPost = pr.post

    if args.cmd == "configure-sdwan":
        configureVWAN()
        sys.exit(0)
    if args.cmd=="commit":
        j = panoramaCommit()
        print("Panorama commit job: {}".format(j))
        waitForJobToFinish(j)
        sys.exit(0)
    if args.cmd=="commit-lcg":
        j = panoramaCommit()
        print("Panorama commit job: {}".format(j))
        waitForJobToFinish(j)
        commitLCG("cg2")
        sys.exit(0)
    if args.cmd=="commit-all":
        enableAutoContentPush()
        j = panoramaCommit()
        print("Panorama commit job: {}".format(j))
        waitForJobToFinish(j)
        d = getDevicesForCommit(connected=True, in_sync=False)
        print(d)
        j = commitDevices(d)
        print("Devices commit job: {}".format(j))
        waitForJobToFinish(j)
        sys.exit(0)
    if args.cmd=="push-all":
        d = getDevicesForCommit(connected=True)
        print(d)
        j = commitDevices(d)
        print("Devices commit job: {}".format(j))
        try:
            waitForJobToFinish(j)
        except commitFailed:
            sys.exit(1)
        else:
            sys.exit(0)
    if args.cmd=="cleanup-devices":
        delicense_jobs = cleanupDevices(
            base_config["min_time_for_device_removal"],
            base_config["permanent_device_groups"],
            todo_dg=args.device_group,
            todo_serial=args.serial,
        )
        print("")
        print("==== First run complete, check delicense jobs")
        for job in delicense_jobs:
            print("Waiting for {} job to complete".format(job))
            waitForJobToFinish(job)
        if len(delicense_jobs)>0:
            print("")
            print("==== Delicense jobs done")
            cleanupDevices(
                base_config["min_time_for_device_removal"],
                base_config["permanent_device_groups"],
                todo_dg=args.device_group,
                todo_serial=args.serial,
            )
        else:
            print("No delicense jobs")
        sys.exit(0)
    if args.cmd=="list-devices":
        printDevices()
        sys.exit(0)
    if args.cmd=="list-licensed-devices":
        lic_devs = getSupportPortalLicensedDevices(None)
        serials = []
        if args.not_on_panorama:
            pan_devs = getDevicesForCommit()
            for s in pan_devs.values():
                serials+= s
        for s in lic_devs:
            if args.not_on_panorama:
                if s not in serials:
                    print("{} {}".format(s, lic_devs[s]))
            else:
                print("{} {}".format(s, lic_devs[s]))
        sys.exit(0)
    if args.cmd=="enable-auto-content-push":
        enableAutoContentPush()
        sys.exit(0)
    if args.cmd=="test-xml-ae-subinterface":
        testXMLAESubinterface()
        sys.exit(0)
    if args.cmd=="register-ip-tag":
        ipTagMapping("register", args.serial, args.ip, "block-ip")
        sys.exit(0)
    if args.cmd=="unregister-ip-tag":
        ipTagMapping("unregister", args.serial, args.ip, "block-ip")
        sys.exit(0)
    if args.cmd=="query-ip-tag":
        iptag = getIPTagMapping(args.serial)
        for ip in iptag:
            print('{} - {}'.format(ip, ','.join(iptag[ip])))
        sys.exit(0)
    if args.cmd=="query-traffic-logs":
        logs = queryLogs('traffic', args.query)
        for e in logs.findall('./entry'):
            #print(etree.tostring(e, pretty_print=True).decode())
            print("{:12}->{:12}:{:4} {:10} {:12}={}".format(
                e.find('src').text, 
                e.find('dst').text, 
                e.find('dport').text,
                e.find('app').text,
                e.find('action').text,
                e.find('rule').text
            ))
        sys.exit(0)
    print("Unrecognized command")
    sys.exit(1)


if __name__ == '__main__':
    sys.exit(main())
