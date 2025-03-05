#!/usr/bin/env python3
import argparse
import base64
import copy
import datetime
import ipaddress
import logging
import logging.handlers
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
import xmltodict


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

base_params = {
    'key': '',
    'type': 'op',
}
base_config = {}
pano_base_url = 'https://{}/api/'.format('dummy')
panoramaRequestGet = None
panoramaRequestPost = None
verbose = False

class commitFailed(Exception):
    pass

class jobFailed(Exception):
    pass

class jobNotFound(Exception):
    pass

class deviceNotConnected(Exception):
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
    base_config['panorama_name'] = data["name"]


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
        self.timeout = (10, 60)   # connect, read
        if self.verify:
            self.rs = requests.session()
        else:
            # SSLError(SSLError(1, '[SSL: UNSAFE_LEGACY_RENEGOTIATION_DISABLED] unsafe legacy renegotiation disabled 
            self.rs = getLegacySSLRequestsSession()

    def verifyResponse(self, params, response):
        if not response.attrib.get('status')=='success':
            if int(response.attrib.get('code'))==13:
                if re.match(r'.* not connected', response.find('./msg/line').text):
                    raise deviceNotConnected('Get sessions failed')
            if int(response.attrib.get('code'))==403 and response.find('./result/msg').text=='API Error: Invalid Credential':
                logger.error('API Error: Invalid Credential')
                raise Exception("API Error: Invalid Credential")
            logger.error('Failed to verify response')
            logger.error(params)
            logger.error(etree.tostring(response, pretty_print=True).decode())
            raise Exception("Failed")

    def get(self, params, returnParsed=False):
        try:
            c = self.rs.get(pano_base_url, params=params, verify=self.verify, timeout=self.timeout).content
        except requests.ConnectTimeout as e:
            logger.error('ConnectTimeout')
            raise e
        try:
            xml_resp = etree.fromstring(c)
        except:
            logger.error("Failed to parse response:")
            logger.error(c)
            raise Exception("Failed to parse response")
        self.verifyResponse(params, xml_resp)
        if returnParsed:
            return xml_resp
        return c

    def post(self, params, files, returnParsed=False):
        try:
            c = self.rs.post(pano_base_url, params=params, files=files, verify=self.verify, timeout=self.timeout).content
        except requests.ConnectTimeout as e:
            logger.error('ConnectTimeout')
            raise e
        try:
            xml_resp = etree.fromstring(c)
        except:
            logger.error("Failed to parse response:")
            logger.error(c)
            raise Exception("Failed to parse response")
        self.verifyResponse(params, xml_resp)
        if returnParsed:
            return xml_resp
        return c


def panoramaCommit():
    params = copy.copy(base_params)
    params['type'] = 'commit'
    r = etree.Element('commit')
    params['cmd'] = etree.tostring(r)
    logger.debug(params)
    resp = panoramaRequestGet(params)
    logger.debug(resp)
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



def handleJob(job_result):
    safe_to_ignore_warnings = [
        r'In virtual-router \w+, BGP export policy only_local_prefixes is enabled but not used by any peer-group'
    ]
    safe_to_ignore_errors = [
        r'Autogenerated SDWAN configuration',
        r'Configuration committed successfully',
        r'Local configuration size',
        r'Merged configuration size.local, panorama pushed, predefined.: \d+ MB',
        r'Maximum recommended merged configuration size: 0 MB .0% configured.',
        r'Panorama connectivity check was successful for .*',
        r'Performing panorama connectivity check .attempt 1 of 1.',
        r'Predefined configuration size: \d+ MB',
    ]
    js = job_result
    result = js.find('./result/job/result').text
    job_type = js.find('./result/job/type').text
    job_id = js.find('./result/job/id').text
    logger.info("Job: {} type: {} result: {}".format(job_id, job_type, result))
    logger.debug(etree.tostring(js, pretty_print=True).decode())
    for d in js.findall('./result/job/devices/entry'):
        dn = d.find('./devicename').text
        sn = d.find('./serial-no').text
        r = d.find('./result').text
        det_msg = ""
        logger.info("== {} / {} - {} - {}".format(dn, sn, r, det_msg))
        warnings = []
        ignored = 0
        for l in d.findall('./details/msg/warnings/line'):
            for sti in safe_to_ignore_warnings:
                if re.match(sti, l.text):
                    ignored+= 1
                    break
            else:
                warnings.append(l.text)
        logger.info("\tWarnings left:{} (and ignored: {})".format(len(warnings), ignored))
        for l in warnings:
            logger.info("\t\t{}".format(l))
        errors = []
        ignored = 0
        try:
            for l in d.findall('./details/msg/errors/line'):
                for sti in safe_to_ignore_errors:
                    if l.text and re.match(sti, l.text):
                        ignored+= 1
                        break
                else:
                    errors.append(l.text)
        except:
            print(etree.tostring(js, pretty_print=True).decode())
            raise Exception("Failed to parse commit message")
        logger.info("\tErrors left:{} (and ignored: {})".format(len(errors), ignored))
        for l in errors:
            logger.info("\t\t{}".format(l))
    if result != "OK":
        if verbose:
            print(etree.tostring(js, pretty_print=True).decode())
        if job_type=="Commit":
            raise commitFailed("")
        else:
            raise jobFailed("")


def waitForJobToFinish(id):
    if id == None:
        print("Job is none")
        return
    while True:
        js = getJobStatus(id)
        if js.attrib.get('code') == '7':
            for l in js.findall('./msg/line'):
                if re.match(r'job \d+ not found', l.text):
                    raise jobNotFound("{}".format(id))
            logger.debug(js)
            raise Exception("unknown error")
        s = js.find('./result/job/status').text
        if s == "FIN":
            break
        time.sleep(5)
    if verbose:
        print(etree.tostring(js, pretty_print=True).decode())
    handleJob(js)



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
                #raise Exception("Device should be disconnected, but most recent log is: {}".format(log))
                print("Device should be disconnected, but most recent log is: {}".format(log))
                return False
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


def getSDWANConfig():
    if not hasattr(getSDWANConfig, "cfg"):
        params = copy.copy(base_params)
        params['type'] = 'config'
        params['action'] = 'get'
        xpath = "/config/devices/entry[@name='localhost.localdomain']"
        xpath+= "/plugins/sd_wan"
        params['xpath'] = xpath
        getSDWANConfig.cfg = etree.fromstring(panoramaRequestGet(params=params)).find('./result/sd_wan')
    cfg = getSDWANConfig.cfg
    return cfg


def findSDWANClusterForDevice(serial):
    cfg = getSDWANConfig()
    if cfg is None:
        return (None, None)
    for i_s in cfg.findall('./vpn-cluster/entry//entry'):
        s = i_s.get('name')
        if s==serial:
            fw_type = i_s.getparent().tag
            cluster_name = i_s.getparent().getparent().get('name')
            return (fw_type, cluster_name)
    return (None, None)


def deleteDeviceFromSDWAN(serial):
    (fw_type, cluster_name) = findSDWANClusterForDevice(serial)
    if cluster_name:
        params = copy.copy(base_params)
        params['type'] = 'config'
        params['action'] = 'delete'
        xpath = "/config/devices/entry[@name='localhost.localdomain']"
        xpath += "/plugins/sd_wan/vpn-cluster/entry[@name='{}']".format(cluster_name)
        xpath += "/{}/entry[@name='{}']".format(fw_type, serial)
        params['xpath'] = xpath
        r = doAPIDeleteFromConfig(params, xpath)
        if r:
            logger.info("{} removed from sdwan cluster {}".format(serial, cluster_name))
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'delete'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/plugins/sd_wan/devices/entry[@name='{}']".format(serial)
    params['xpath'] = xpath
    r = doAPIDeleteFromConfig(params, xpath)
    if r:
        logger.info("{} removed from sdwan".format(serial))
    return r


def deleteDeviceFromDG(serial, dg):
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'delete'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/device-group/entry[@name='{}']/devices/entry[@name='{}']".format(dg, serial)
    params['xpath'] = xpath
    r = doAPIDeleteFromConfig(params, xpath)
    logger.info("{} {}removed from dg {}".format(serial, "" if r else "not ", dg))
    return r


def addDeviceToTS(serial, ts):
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'set'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/template-stack/entry[@name='{}']/devices".format(ts)
    params['xpath'] = xpath
    r = etree.Element('entry')
    r.attrib['name'] = serial
    params['element'] = etree.tostring(r)
    submitConfigChange(params)
    print("{} added to ts {}".format(serial, ts))


def deleteDeviceFromTS(serial, ts):
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'delete'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/template-stack/entry[@name='{}']/devices/entry[@name='{}']".format(ts, serial)
    params['xpath'] = xpath
    r = doAPIDeleteFromConfig(params, xpath)
    logger.info("{} {}removed from ts {}".format(serial, "" if r else "not ", ts))
    return r


def deleteDeviceFromLCG(serial, lcg):
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'delete'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/log-collector-group/entry[@name='{}']/logfwd-setting/devices/entry[@name='{}']".format(lcg, serial)
    params['xpath'] = xpath
    r = doAPIDeleteFromConfig(params, xpath)
    logger.info("{} {}removed from lcg {}".format(serial, "" if r else "not ", lcg))
    return r


def deleteDeviceFromPanoramaDevices(serial):
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'delete'
    xpath = "/config/mgt-config/devices/entry[@name='{}']".format(serial)
    params['xpath'] = xpath
    r = doAPIDeleteFromConfig(params, xpath)
    logger.info("{} {}removed from panorama device list".format(serial, "" if r else "not "))
    return r


def configureAzureResourceGroupInTemplate(template, resource_group):
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'set'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/template/entry[@name='{}']".format(template)
    xpath+= "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/deviceconfig/plugins/vm_series/azure-ha-config"
    params['xpath'] = xpath
    r = etree.Element('resource-group')
    r.text = resource_group
    params['element'] = etree.tostring(r)
    resp = etree.fromstring(panoramaRequestGet(params))
    rtxt = etree.tostring(resp).decode()
    if not resp.attrib.get('status') == 'success':
        print(resp)
        raise Exception("Config operation did not succeed: {} {}".format(xpath, rtxt))


def applyTemplateConfigurations():
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'get'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath+= "/template"
    params['xpath'] = xpath
    ts = etree.fromstring(panoramaRequestGet(params))
    for i_t in ts.findall('./result/template/entry'):
        t_name = i_t.get('name')
        desc_n = i_t.find('description')
        if desc_n is None:
            continue
        if mre:=re.match(r'azrg:([^ ]+)', desc_n.text):
            azrg = mre[1]
            configureAzureResourceGroupInTemplate(t_name, azrg)


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
    device_found = False
    delicense_jobs = []
    params = copy.copy(base_params)
    r = etree.Element('show')
    s = etree.SubElement(r, 'devices')
    s = etree.SubElement(s, 'all')
    params['cmd'] = etree.tostring(r)
    resp = etree.fromstring(panoramaRequestGet(params))
    lic_devs = getSupportPortalLicensedDevices()
    for i_d in resp.findall('./result/devices/entry'):
        serial = i_d.find('serial').text
        connected = i_d.find('connected').text
        if todo_serial is not None and todo_serial!=serial:
            continue
        dg = getDGOfDevice(serial)
        if dg in stable_dgs:
            logger.debug("Do not delete {} based on dg {} membership".format(serial, dg))
            continue
        if todo_dg is not None:
            if not (todo_dg=='orphaned' and dg is None):
                if dg!=todo_dg:
                    logger.debug("Do not delete {} different dg {}".format(serial, dg))
                    continue
        if todo_dg is None and todo_serial is None:
            query = "(description contains '{} connected')".format(serial)
            query+= "or (description contains '{} disconnected') ".format(serial)
            query+= "or (description contains 'successfully authenticated for bootstrapped device {}') ".format(serial)
            logs = queryLogs('system', query)
            if not isDeviceCandidateForRemovalBasedOnHistory(logs, min_time):
                logger.debug("Not suitable for delete {}, too fresh".format(serial))
                continue
        if todo_serial is None and connected=="yes":
            logger.warn("Not suitable for delete {}, still connected".format(serial))
            continue
        if serial in lic_devs:
            logger.info("Needs to be delicensed first {}".format(lic_devs[serial]))
            job = delicenseFirewallFromPanorama(serial)
            delicense_jobs.append(job)
            device_found = True
            continue
        device_found = True
        ts = getTSOfDeviceFromConfig(serial)
        lcg = getLCGOfDevice(serial)
        logger.info("Will delete {}, dg: {}, ts: {}, lcg: {}".format(serial, dg, ts, lcg))
        deleteDeviceFromSDWAN(serial)
        if dg:
            deleteDeviceFromDG(serial, dg)
        if ts:
            deleteDeviceFromTS(serial, ts)
        if lcg:
            deleteDeviceFromLCG(serial, lcg)
        deleteDeviceFromPanoramaDevices(serial)
    return (device_found, delicense_jobs)


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
    logger.debug(params['cmd'])
    xml_resp = panoramaRequestGet(params, returnParsed=True)
    msg = xml_resp.find('.//msg').text
    if msg == "There are no changes to commit.":
        logger.info(msg)
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
    xml_resp = panoramaRequestGet(params, returnParsed=True)
    for l in xml_resp.findall('./msg/line'):
        logger.info(l.text)
    return None


def summarizeCommitStatus(commit_status, sync_status):
    if commit_status == 'commit failed':
        return '--- FAILED ---'
    elif commit_status == 'not connected':
        return '({})'.format(sync_status)
    elif commit_status == 'commit succeeded with warnings':
        return '{} ({})'.format('warnings', sync_status)
    elif commit_status == 'commit succeeded':
        return '{} ({})'.format('succeeded', sync_status)
    return '{} ({})'.format(commit_status, sync_status)


def getConfigStatusOfDevice(serial):
    if not hasattr(getConfigStatusOfDevice, "dgs"):
        params = copy.copy(base_params)
        r = etree.Element('show')
        s = etree.SubElement(r, 'devicegroups')
        params['cmd'] = etree.tostring(r)
        getConfigStatusOfDevice.dgs = etree.fromstring(panoramaRequestGet(params=params))
    if not hasattr(getConfigStatusOfDevice, "tss"):
        params = copy.copy(base_params)
        r = etree.Element('show')
        s = etree.SubElement(r, 'template-stack')
        params['cmd'] = etree.tostring(r)
        getConfigStatusOfDevice.tss = etree.fromstring(panoramaRequestGet(params=params))
    dgs = getConfigStatusOfDevice.dgs
    tss = getConfigStatusOfDevice.tss
    r = {
       'dg': '-',
       'dg_status': '-',
       'policy': {
           'sync_status': '-',
           'commit_status': '-',
       },
       'ts': '-',
       'ts_status': '-',
       'template': {
           'sync_status': '-',
           'commit_status': '-',
       },
    }
    for i_dg in dgs.findall('./result/devicegroups/entry'):
        dg_name = i_dg.get('name')
        for i_dev in i_dg.findall('./devices/entry'):
            if serial == i_dev.find('serial').text:
                try:
                    r['dg'] = dg_name
                    r['policy']['sync_status'] = i_dev.find('shared-policy-status').text
                    r['policy']['commit_status'] = i_dev.find('last-commit-all-state-sp').text
                except:
                    pass
                r['dg_status'] = summarizeCommitStatus(r['policy']['commit_status'], r['policy']['sync_status'])
                break
    for i_ts in tss.findall('./result/template-stack/entry'):
        ts_name = i_ts.get('name')
        for i_ts in i_ts.findall('./devices/entry'):
            if serial == i_ts.find('serial').text:
                try:
                    r['ts'] = ts_name
                    r['template']['sync_status'] = i_ts.find('template-status').text
                    r['template']['commit_status'] = i_ts.find('last-commit-all-state-tpl').text
                except:
                    pass
                r['ts_status'] = summarizeCommitStatus(r['template']['commit_status'], r['template']['sync_status'])
                break
    return r


def getDevicesInDG(dg):
    serials = []
    if not hasattr(getDevicesInDG, "dgs"):
        params = copy.copy(base_params)
        r = etree.Element('show')
        s = etree.SubElement(r, 'devicegroups')
        s = etree.SubElement(s, 'name')
        s.text = dg
        params['cmd'] = etree.tostring(r)
        getDevicesInDG.dgs = etree.fromstring(panoramaRequestGet(params=params))
    dgs = getDevicesInDG.dgs
    for i_dg in dgs.findall('./result/devicegroups/entry'):
        for i_dev in i_dg.findall('./devices/entry'):
            serials.append(i_dev.find('serial').text)
    return serials


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


def getLCGs():
    lcgsr = []
    if not hasattr(getLCGs, "lcgs"):
        params = copy.copy(base_params)
        r = etree.Element('show')
        s = etree.SubElement(r, 'log-collector-group')
        s = etree.SubElement(s, 'all')
        params['cmd'] = etree.tostring(r)
        getLCGs.lcgs =  etree.fromstring(panoramaRequestGet(params=params))
    lcgs = getLCGs.lcgs
    for i_lcg in lcgs.findall('./result/log-collector-group/entry'):
        lcg_name = i_lcg.get('name')
        lcgsr.append(lcg_name)
    return lcgsr


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

def getDevices(connected=None):
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
        d = {}
        for e in ['connected', 'dg', 'dg_status', 'ha', 'hostname', 'ip', 'logging-status', 'model', 'sw-version', 'ts', 'ts_status']:
            d[e] = '-'
        d['serial'] = serial
        #print(etree.tostring(i_d, pretty_print=True).decode())
        try:
            # manually added devices which never connected to panorama will not have these details
            d['ip'] = i_d.find('ip-address').text
            d['hostname'] = i_d.find('hostname').text
            d['model'] = i_d.find('model').text
            d['sw-version']= i_d.find('sw-version').text
            d['ha']= i_d.find('ha/state').text
        except:
            pass
        dg = getDGOfDevice(serial)
        ts = getTSOfDevice(serial)
        cs = getConfigStatusOfDevice(serial)
        if i_d.find('connected').text == "yes":
            d['connected'] = 'yes'
        if getLoggingStatusOfDevice(serial) is True:
            d['logging-status'] = 'yes'
        if dg is not None:
            d['dg'] = dg
        if ts is not None:
            d['ts'] = ts
        d['dg_status'] = cs['dg_status']
        d['ts_status'] = cs['ts_status']
        if connected is not None:
            if connected==False and d['connected'] == 'yes':
                continue
            if connected==True and d['connected'] == '-':
                continue
        devs[serial] = d
    return devs

def printDevices(connected=None):
    devs = getDevices(connected)
    headers = [
        'hostname',
        'ip',
        'serial',
        'dg',
        'ts',
        'connected',
        'logging',
        'sw',
        'model',
        'ha',
        'dg_status',
        'ts_status',
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
            d['model'],
            d['ha'],
            d['dg_status'],
            d['ts_status'],
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
            try:
                policy_status = i_dev.find('shared-policy-status').text
            except:
                policy_status = None
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


def getSupportPortalLicensedDevicesForAuthCode(devices, authcode):
    url = "https://api.paloaltonetworks.com/api/license/get"
    api_key = base_config["license"]["api_key"]
    headers = {
        "apikey": api_key
    }
    data = {
        "authcode": authcode
    }
    resp = requests.post(url, data=data, headers=headers, verify=False)
    if resp.status_code!=200:
        print(resp)
        raise Exception("Invalid response: code:{}, {}".format(resp.status_code, resp.content))
    devs = json.loads(resp.content)
    for d in devs['UsedDeviceDetails']:
        d['authcode'] = authcode
        sn = d.get('SerialNumber')
        devices[sn] = d


def getSupportPortalLicensedDevices():
    devices = {}
    for authcode in base_config["license"]["authcodes"]:
      getSupportPortalLicensedDevicesForAuthCode(devices, authcode)
    return devices


def getOauthTokenSoftwareFirewallLicensingAPI():
    if hasattr(getOauthTokenSoftwareFirewallLicensingAPI, "token"):
        return getOauthTokenSoftwareFirewallLicensingAPI.token
    url = "https://identity.paloaltonetworks.com/as/token.oauth2"
    client_id = base_config["license"]["sw_ngfw_licensing_api"]["client_id"]
    client_secret = base_config["license"]["sw_ngfw_licensing_api"]["client_secret"]
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "fwflex-service",
        "grant_type": "client_credentials"
    }
    resp = requests.post(url, data=data, headers=headers, verify=False)
    data = json.loads(resp.text)
    token = data["access_token"]
    getOauthTokenSoftwareFirewallLicensingAPI.token = token
    return token


def getLicensedDevicesForAuthCodeSoftwareFirewallLicensingAPI(token, devices, authcode):
    url = "https://api.paloaltonetworks.com/tms/v1/firewallserialnumbers"
    headers = {
        "token": token
    }
    params = {
        "auth_code": authcode
    }
    resp = requests.get(url, params=params, headers=headers, verify=False)
    data = json.loads(resp.text)
    for vm in data["vm_series"]:
        devices[vm] = {}
        devices[vm]['authcode'] = authcode


def getLicensedDevicesSoftwareFirewallLicensingAPI():
    devices = {}
    token = getOauthTokenSoftwareFirewallLicensingAPI()
    for authcode in base_config["license"]["authcodes"]:
        getLicensedDevicesForAuthCodeSoftwareFirewallLicensingAPI(token, devices, authcode)
    return devices


def getDeploymentProfileSoftwareFirewallLicensingAPI(token, dps, authcode):
    url = "https://api.paloaltonetworks.com/tms/v1/deploymentProfile/{}".format(authcode)
    headers = {
        "token": token
    }
    resp = requests.get(url, headers=headers, verify=False)
    data = json.loads(resp.text)
    dps[authcode] = data["data"]


def getDeploymentProfilesSoftwareFirewallLicensingAPI():
    token = getOauthTokenSoftwareFirewallLicensingAPI()
    dps = {}
    for authcode in base_config["license"]["authcodes"]:
        getDeploymentProfileSoftwareFirewallLicensingAPI(token, dps, authcode)
    return dps


def delicenseFirewallFromPanorama(serial):
    # request batch license deactivate VM-Capacity devices 0079xxxxxxxxxx4 mode auto
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
    xml_resp = panoramaRequestGet(params, returnParsed=True)
    job = xml_resp.find('.//job').text
    logger.info("Delicense job {} triggered for {}".format(job, serial))
    return job

def ipTagMapping(op, serial, ip, tag, timeout=12*3600):
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
    e.attrib['persistent'] = "1"
    t = etree.SubElement(e, 'tag')
    m = etree.SubElement(t, 'member')
    m.attrib['timeout'] = str(timeout)
    m.text = tag
    # print(etree.tostring(um, pretty_print=True).decode())
    params['type'] = 'user-id'
    if serial is not None:
        params['target'] = serial
    files = { 'file': ('file', etree.tostring(um), 'text/xml')}
    panoramaRequestPost(params, files)
    # print(resp.request.headers)
    # print(resp.request.url)
    # print(resp.request.body)
    # print(resp.content)
    # print(etree.tostring(xml_resp, pretty_print=True).decode())

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


def getDynamicAddressGroup(dag, dg=None, serial=None):
    ips = set()
    assert(serial or dg)
    params = copy.copy(base_params)
    r = etree.Element('show')
    s = etree.SubElement(r, 'object')
    s = etree.SubElement(s, 'dynamic-address-group')
    s = etree.SubElement(s, 'name')
    s.text = dag
    params['cmd'] = etree.tostring(r)
    if serial is not None:
        params['target'] = serial
    else:
        params['vsys'] = dg
    resp = panoramaRequestGet(params, returnParsed=True)
    print(etree.tostring(resp, pretty_print=False).decode())
    for e in resp.findall('./result/dyn-addr-grp/entry/member-list/entry'):
        ip = e.get('name')
        ips.add(ip)
    return ips


def getTSs():
    if not hasattr(getTSs, "tss"):
        params = copy.copy(base_params)
        params['type'] = 'config'
        params['action'] = 'get'
        xpath = "/config/devices/entry[@name='localhost.localdomain']"
        xpath+= "/template-stack"
        params['xpath'] = xpath
        getTSs.tss =  etree.fromstring(panoramaRequestGet(params=params))
    return getTSs.tss

def getTSValue(ts, path):
    tss = getTSs()
    for i_ts in tss.findall('./result/template-stack/entry'):
        ts_name = i_ts.get('name')
        if ts_name!=ts:
            continue
        for i_p in i_ts.findall(path):
            return i_p.text
    raise KeyError("path {} not found in {}".format(path, ts))


def getTSVariable(ts, variable):
    tss = getTSs()
    for i_ts in tss.findall('./result/template-stack/entry'):
        ts_name = i_ts.get('name')
        if ts_name!=ts:
            continue
        for i_v in i_ts.findall('./variable/entry[@name="{}"]'.format("$"+variable)):
            for i_t in i_v.findall('./type/as-number'):
                return i_t.text
            for i_t in i_v.findall('./type/ip-netmask'):
                return i_t.text
    raise KeyError("variable {} not found in {}".format(variable, ts))



def getUserIPMapping(serial):
    iptag = {}
    params = copy.copy(base_params)
    r = etree.Element('show')
    s = etree.SubElement(r, 'user')
    s = etree.SubElement(s, 'ip-user-mapping-mp')
    s = etree.SubElement(s, 'all')
    params['cmd'] = etree.tostring(r)
    if serial is not None:
        params['target'] = serial
    resp = panoramaRequestGet(params)
    print(resp)
    try:
        xml_resp = etree.fromstring(resp)
    except:
        raise Exception("Failed parsing resp for registered-ip: ".format(resp))
    if not xml_resp.attrib.get('status') == 'success':
        raise Exception("Operation failed: {}".format(resp))
    for e in xml_resp.findall('./result/entry'):
        ip = e.find('ip').text
        user = e.find('user').text
        timeout = e.find('timeout').text
        print("{} {} {}".format(ip, user, timeout))
    

def userIPMapping(op, serial, user, ip):
    assert(op in ['login', 'logout'])
    assert(ip is not None)
    assert(user is not None)
    params = copy.copy(base_params)
    um = etree.Element('uid-message')
    t = etree.SubElement(um, 'version')
    t.text = '1.0'
    t = etree.SubElement(um, 'type')
    t.text = 'update'
    p = etree.SubElement(um, 'payload')
    o = etree.SubElement(p, op)
    e = etree.SubElement(o, 'entry')
    e.attrib['name'] = user
    e.attrib['ip'] = ip
    if op!='logout':
        e.attrib['timeout'] = str(1*1818)
    params['type'] = 'user-id'
    print(etree.tostring(um, pretty_print=False).decode())
    if serial is not None:
        params['target'] = serial
    files = { 'file': ('file', etree.tostring(um), 'text/xml')}
    resp = panoramaRequestPost(params, files)
    xml_resp = etree.fromstring(resp)
    if not xml_resp.attrib.get('status') == 'success':
        print(resp)
        raise Exception(
            "user-ip operation did not succeed: {}".format(resp))



def getSessions(serial):
    params = copy.copy(base_params)
    r = etree.Element('show')
    s = etree.SubElement(r, 'session')
    s = etree.SubElement(s, 'all')
    params['cmd'] = etree.tostring(r)
    params['target'] = serial
    resp = panoramaRequestGet(params)
    xd = xmltodict.parse(resp, force_list={'entry'})
    if xd['response']['@status']=='success':
      if xd['response']['result']==None:
          return []
      try:
        for s in xd['response']['result']['entry']:
            s['serial'] = serial
            try:
                s['security-rule']
            except:
                s['security-rule'] = None
        return xd['response']['result']['entry']
      except Exception as e:
        print(s)
        print(e)
        return []
    # print("Response:")
    # print(xd)
    raise Exception("Failed request")


def printSessions(serial, all=False):
    sessions = []
    if not isinstance(serial, list):
        serial = [serial]
    for s in serial:
        try:
            sessions+= getSessions(s)
        except deviceNotConnected:
            print("Device {} not connected".format(s))
            pass
    headers = [
        'id',
        'org flow',
        'nat flow',
        'nat',
        'zones',
        'proto',
        'app',
        'state',
        'byte-count',
        'rule',
    ]
    if (len(serial)>0):
        headers.append('serial')
    tsessions = []
    ignored_sessions = 0
    for s in sessions:
        # print(s)
        o_src_tuple = s['source'] + ':' + s['sport']
        x_src_tuple = s['xsource'] + ':' + s['xsport']
        o_dst_tuple = s['dst'] + ':' + s['dport']
        x_dst_tuple = s['xdst'] + ':' + s['xdport']
        nat = ''
        if o_src_tuple != x_src_tuple:
            nat+= 'x >'
        else:
            nat+= 'o >'
        if o_dst_tuple != x_dst_tuple:
            nat+= ' x'
        else:
            nat+= ' o'
        if not all:
            if s['application'] in ['pan-health-check', 'pan-login']:
                if s['state']=='ACTIVE':
                    ignored_sessions+= 1
                    continue
            elif s['application'] in ['ntp-base']:
                ignored_sessions+= 1
                continue
            elif s['source'] in ['168.63.129.16']:
                if s['state']=='ACTIVE':
                    ignored_sessions+= 1
                    continue
            elif s['dport'] in ['3978']:
                if s['state']=='ACTIVE':
                    ignored_sessions+= 1
                    continue
        row = [
            s['idx'],
            '{:22} -> {:22}'.format(o_src_tuple, o_dst_tuple),
            '{:22} -> {:22}'.format(x_src_tuple, x_dst_tuple),
            nat,
            '{:9} -> {}'.format(s['from'], s['to']),
            s['proto'],
            s['application'],
            s['state'],
            s['total-byte-count'],
            s['security-rule'],
        ]
        if len(serial)>0:
            row.append(s['serial'])
        tsessions.append(row)
    print("Retrieved {} sessions, ignored {} and {} remained".format(len(sessions), ignored_sessions, len(sessions)-ignored_sessions))
    if (len(sessions)-ignored_sessions)==0:
        return
    print(tabulate(sorted(tsessions, key=operator.itemgetter(2)), headers=headers))
    return



def executeOpCommand(serial, etree_command):
    params = copy.copy(base_params)
    params['cmd'] = etree.tostring(etree_command)
    if serial is not None:
        params['target'] = serial
    logger.debug(etree.tostring(etree_command).decode())
    resp = panoramaRequestGet(params)
    return resp



def runCommand(serial, command):
    commands_with_last_element_as_text = [
      ['clear', 'session', 'all', 'filter', 'destination-port'],
      ['show', 'interface'],
      ['show', 'user', 'ts-agent', 'state'],
      ['show', 'running', 'resource-monitor', 'minute', 'last'],
      ['show', 'running', 'resource-monitor', 'second', 'last'],
    ]
    commands_with_last_element_as_entry = [
      ['show', 'arp'],
    ]
    r = etree.Element(command[0])
    s = None
    for i,c in enumerate(command):
        if s is None:
            s = r
            continue
        if (i+1)==len(command) and command[:-1] in commands_with_last_element_as_text:
            s.text = c
        elif (i+1)==len(command) and command[:-1] in commands_with_last_element_as_entry:
            s = etree.SubElement(s, 'entry')
            s.attrib['name'] = c
        else:
            s = etree.SubElement(s, c)
    print(etree.tostring(r).decode())
    resp = executeOpCommand(serial, r)
    if command and command==['show', 'devices', 'connected']:
        # workaround
        resp = re.sub(r'Total Connected Devices: \d+', '', resp.decode())
    parser = etree.XMLParser(remove_blank_text=True)
    xml_resp = etree.fromstring(resp, parser)
    print(etree.tostring(xml_resp, pretty_print=True).decode())




def clearBGPSessions(serial):
    r = etree.Element('clear')
    s = etree.SubElement(r, 'session')
    s = etree.SubElement(s, 'all')
    s = etree.SubElement(s, 'filter')
    s = etree.SubElement(s, 'destination-port')
    s.text = '179'
    resp = executeOpCommand(serial, r)
    print(resp)


def clearHealthCheckSessions(serial):
    r = etree.Element('clear')
    s = etree.SubElement(r, 'session')
    s = etree.SubElement(s, 'all')
    s = etree.SubElement(s, 'filter')
    s = etree.SubElement(s, 'application')
    s.text = 'pan-health-check'
    resp = executeOpCommand(serial, r)
    print(resp)


def submitConfigChange(params):
    xml_resp = panoramaRequestGet(params, returnParsed=True)
    rtxt = etree.tostring(xml_resp).decode()
    if xml_resp.attrib.get('code') == '20':
        # success, command succeeded
        msg = xml_resp.find('msg').text
        if msg == "command succeeded":
            return True
    logger.error('Unknown response for config operation:')
    logger.error(rtxt)
    raise Exception("Unknown response for config operation: {} {}".format(params['xpath'], rtxt))


def buildSDWANDeviceConfig(dev_root, props):
    es = etree.SubElement(dev_root, 'entry')
    es.attrib['name'] = props['serial']
    ebgp = etree.SubElement(es, 'bgp')
    e = etree.SubElement(ebgp, 'router-id')
    e.text = props['router_id']
    e = etree.SubElement(ebgp, 'loopback-address')
    e.text = props['router_id']
    e = etree.SubElement(ebgp, 'as-number')
    e.text = props['asn']
    e = etree.SubElement(es, 'router-name')
    e.text = props['vr']
    e = etree.SubElement(es, 'type')
    e.text = props['type']
    e = etree.SubElement(es, 'site')
    e.text = props['site']
    e = etree.SubElement(ebgp, 'ipv4-bgp-enable')
    e.text = 'yes'
    e = etree.SubElement(ebgp, 'remove-private-as')
    e.text = 'no'
    e = etree.SubElement(es, 'vpn-tunnel')
    e = etree.SubElement(e, 'authentication')
    e = etree.SubElement(e, 'pre-shared-key')
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


def configureSDWAN():
    params = copy.copy(base_params)
    params['type'] = 'config'
    params['action'] = 'set'
    xpath = "/config/devices/entry[@name='localhost.localdomain']"
    xpath += "/plugins/sd_wan"
    params['xpath'] = xpath
    devs = {}
    print("Collecting SDWAN config")
    azc = AzureClient(subscription_id=base_config['azure']['subscription_id'], owner_tag_value=base_config['azure']['owner_tag'])
    for d in getDevices(True).values():
        hostname = d['hostname']
        if not 'vwan' in hostname:
            continue
        if not 'sdwan' in hostname:
            continue
        print("Finding VM {} in azure...\r".format(hostname), end='\r')
        vmid = azc.findVMIDByName(hostname)
        print("Getting {} IPs...{:50}\r".format(hostname, " "), end='\r')
        sys.stdout.flush()
        ips = azc.getVMIPs(vmid)
        print("Done {:50}\r".format(hostname, " "), end='\r')
        sdwan_node = hostname
        devs[hostname] = {
            "public_ips": {},
            "prefixes": []
        }
        ts_desc = getTSValue(d['ts'], './/description')
        if mre:=re.match(r'.*pat:sdwan:hub:([\d+]).*', ts_desc):
            devs[hostname]['type'] = 'hub'
            devs[hostname]['prio'] = mre[1]
            devs[hostname]['prefixes'].append("172.16.0.0/16")
        else:
            devs[hostname]['type'] = 'branch'
            prv_route = getTSValue(d['ts'], './/network/virtual-router/entry[@name="vr1"]/routing-table/ip/static-route/entry[@name="prv"]/destination')
            devs[hostname]['prefixes'].append(prv_route)
        devs[hostname]['serial']    = d['serial']
        devs[hostname]['asn']       = getTSValue(d['ts'], './/network/virtual-router/entry[@name="vr1"]/protocol/bgp/local-as')
        devs[hostname]['router_id'] = getTSValue(d['ts'], './/network/virtual-router/entry[@name="vr1"]/protocol/bgp/router-id')
        devs[hostname]['site']      = hostname
        devs[hostname]['vr']        = 'vr1'
        print(f"{hostname:35} {devs[hostname]['serial']} {devs[hostname]['type']}")
        for intf in ips:
            if intf.endswith('internet') or intf.endswith('isp1'):
                devs[sdwan_node]['public_ips']['ethernet1/1'] = ips[intf]['primary']['public_ip_address']
            if intf.endswith('isp2'):
                devs[sdwan_node]['public_ips']['ethernet1/2'] = ips[intf]['primary']['public_ip_address']
    dr = etree.Element('devices')
    for d in devs.values():
        buildSDWANDeviceConfig(dr, d)
    params['element'] = etree.tostring(dr)
    # print(etree.tostring(dr, pretty_print=True).decode())
    print("Submiting SDWAN devices")
    submitConfigChange(params)

    # cluster
    cr = etree.Element('vpn-cluster')
    ec = etree.SubElement(cr, 'entry')
    ec.attrib['name'] = "azure-vwan"
    ect = etree.SubElement(ec, 'type')
    ect.text = 'hub-spoke'
    # ect.text = 'mesh'
    ect = etree.SubElement(ec, 'authentication_type')
    ect.text = 'pre-shared-key'
    eb = etree.SubElement(ec, 'branches')
    for d in devs.values():
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
    # print(etree.tostring(cr, pretty_print=True).decode())
    params['element'] = etree.tostring(cr)
    print("Submiting SDWAN cluster")
    submitConfigChange(params)
    print("SDWAN config completed")


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
        assert(vm_id)
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



def setupLogging(panorama_name):
    ldate = '%Y-%m-%d %H:%M:%S'

    logger.setLevel(logging.DEBUG)

    lhd = logging.handlers.RotatingFileHandler('/Users/rweglarz/pat-{}.debug'.format(panorama_name), mode='a', maxBytes=10*1024*1024, backupCount=2)
    lhd.setLevel(logging.DEBUG)
    lhd.setFormatter(logging.Formatter(fmt='%(asctime)s %(filename)s:%(lineno)d %(message)s', datefmt=ldate))
    logging.getLogger().addHandler(lhd)

    lhs = logging.StreamHandler(sys.stdout)
    lhs.setLevel(logging.INFO)
    logging.getLogger().addHandler(lhs)



def main():
    parser = argparse.ArgumentParser(
        description='useful actions on panorama'
    )
    #parser.add_argument('--clean', action='store_true')
    parser.add_argument('--all', action='store_true')
    parser.add_argument('--panorama-creds-file', nargs='?', action='store')
    parser.add_argument('--serial', nargs='?', action='store')
    parser.add_argument('--ip', nargs='?', action='store')
    parser.add_argument('--dynamic-address-group', nargs='?', action='store')
    parser.add_argument('--device-group', nargs='?', action='store')
    parser.add_argument('--template-stack', nargs='?', action='store')
    parser.add_argument('--not-on-panorama', action='store_true')
    parser.add_argument('--query', nargs='?', action='store')
    parser.add_argument('--tag', nargs='?', action='store')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--command', nargs=argparse.REMAINDER)
    parser.add_argument('cmd')
    args = parser.parse_args()

    readConfiguration(panorama_creds_file=args.panorama_creds_file)
    setupLogging(base_config['panorama_name'])
    logger.debug('args: {}'.format(args.cmd))

    if args.serial and ',' in args.serial:
        args.serial = args.serial.split(',')
    
    if args.verbose:
        global verbose
        verbose = True

    pr = panoramaRequest(verify=False)
    global panoramaRequestGet
    panoramaRequestGet = pr.get
    global panoramaRequestPost
    panoramaRequestPost = pr.post

    if args.cmd == "configure-sdwan":
        configureSDWAN()
        sys.exit(0)
    if args.cmd=="assign-ts":
        old_ts = getTSOfDeviceFromConfig(args.serial)
        deleteDeviceFromTS(args.serial, old_ts)
        addDeviceToTS(args.serial, args.template_stack)
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
        lcgs = getLCGs()
        for lcg in lcgs:
            print("Commiting {}".format(lcg))
            j = commitLCG(lcg)
        sys.exit(0)
    if args.cmd=="commit-all":
        enableAutoContentPush()
        applyTemplateConfigurations()
        j = panoramaCommit()
        if j is None:
            print("Nothing to commit to panorama, done here")
            sys.exit(0)
        print("Panorama commit job: {}".format(j))
        try:
            waitForJobToFinish(j)
        except commitFailed:
            sys.exit(1)
        d = getDevicesForCommit(connected=True, in_sync=False)
        if len(d)==0:
            print("No devices to commit, push to all")
            d = getDevicesForCommit(connected=True)
        print(d)
        j = commitDevices(d)
        print("Devices commit job: {}".format(j))
        try:
            waitForJobToFinish(j)
        except commitFailed:
            sys.exit(1)
        sys.exit(0)
    if args.cmd=="push-all":
        d = getDevicesForCommit(connected=True)
        print(d)
        j = commitDevices(d)
        print("Devices commit job: {}".format(j))
        try:
            waitForJobToFinish(j)
        except jobFailed:
            sys.exit(1)
        else:
            sys.exit(0)
    if args.cmd=="cleanup-devices":
        (device_found, delicense_jobs) = cleanupDevices(
            base_config["min_time_for_device_removal"],
            base_config["permanent_device_groups"],
            todo_dg=args.device_group,
            todo_serial=args.serial,
        )
        if not device_found:
            logger.error('No devices to delicense found')
            sys.exit(1)
        print("")
        print("==== First run complete, check delicense jobs")
        for job in delicense_jobs:
            print("Waiting for {} job to complete".format(job))
            try:
                waitForJobToFinish(job)
            except jobFailed as e:
                print("Job {} failed: ".format(job, e))
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
        connected = True
        if args.all:
            connected = None
        printDevices(connected)
        sys.exit(0)
    if args.cmd=="list-licensed-devices":
        lic_devs = getSupportPortalLicensedDevices()
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
    if args.cmd=="swfw-list-licensed-devices":
        lic_devs = getLicensedDevicesSoftwareFirewallLicensingAPI()
        dps = getDeploymentProfilesSoftwareFirewallLicensingAPI()
        for s in lic_devs:
            authcode = lic_devs[s]["authcode"]
            print("{} {} {}".format(s, lic_devs[s]["authcode"], dps[authcode]["profileName"]))
        sys.exit(0)
    if args.cmd=="enable-auto-content-push":
        enableAutoContentPush()
        sys.exit(0)
    if args.cmd=="test-xml-ae-subinterface":
        testXMLAESubinterface()
        sys.exit(0)
    if args.cmd=="register-ip-tag":
        ipTagMapping("register", args.serial, args.ip, args.tag)
        sys.exit(0)
    if args.cmd=="unregister-ip-tag":
        ipTagMapping("unregister", args.serial, args.ip, args.tag)
        sys.exit(0)
    if args.cmd=="query-ip-tag":
        iptag = getIPTagMapping(args.serial)
        for ip in iptag:
            print('{} - {}'.format(ip, ','.join(iptag[ip])))
        sys.exit(0)
    if args.cmd == "query-dynamic-address-group":
        ips = getDynamicAddressGroup(dag=args.dynamic_address_group, dg=args.device_group, serial=args.serial)
        for ip in sorted(ips, key=ipaddress.IPv4Address):
            print(ip)
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
    if args.cmd == "list-sessions":
        if args.device_group:
            serials = getDevicesInDG(args.device_group)
        else:
            serials = args.serial
        printSessions(serials, args.all)
        sys.exit(0)
    if args.cmd == "show-running-security-policy":
        r = etree.Element('show')
        s = etree.SubElement(r, 'running')
        s = etree.SubElement(s, 'security-policy')
        executeOpCommand(args.serial, r)
        sys.exit(0)
    if args.cmd == "command":
        runCommand(args.serial, args.command)
        sys.exit(0)
    if args.cmd == "block-bgp":
        ipTagMapping("register", args.serial, '0.0.0.0/0', "block-bgp")
        clearBGPSessions(args.serial)
        sys.exit(0)
    if args.cmd == "unblock-bgp":
        ipTagMapping("unregister", args.serial, '0.0.0.0/0', "block-bgp")
        sys.exit(0)
    if args.cmd == "block-health-check":
        ipTagMapping("register", args.serial, '0.0.0.0/0', "block-hc", 3600)
        clearHealthCheckSessions(args.serial)
        sys.exit(0)
    if args.cmd == "unblock-health-check":
        ipTagMapping("unregister", args.serial, '0.0.0.0/0', "block-hc")
        sys.exit(0)
    print("Unrecognized command")
    sys.exit(1)


if __name__ == '__main__':
    sys.exit(main())
