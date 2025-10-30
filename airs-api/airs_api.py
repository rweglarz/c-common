#!/usr/bin/env python3

import argparse
import json
import os
import requests
import time


sync_url   = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"
async_url  = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/async/request"
scan_url   = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/results"
report_url = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/reports"

headers = {
    'x-pan-token': 'fill it in or use xpantoken env value',
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

base_req = {
    "ai_profile": {
        "profile_name": "fill it on or use aiprofilename env value"
    }
}



def makeSyncRequest(chats, print_report):
    print()
    print("Sync requests")
    for chat in chats:
        print(chat)
        req = dict(base_req)
        req["contents"] = chats[chat]
        req["tr_id"] = chat
        print(chats[chat][0]["prompt"])
        response = requests.post(sync_url, json = req, headers = headers)
        json_data = json.loads(response.text)
        print(json.dumps(json_data, indent=4))
        if "error" in json_data:
            exit(1)
        recommendedAction = json_data['action']
        print("The recommended action for this prompt is: {}".format(recommendedAction))
        print()
        if print_report:
            print("====== report")
            rr = getReportId(json_data["report_id"])
            print(json.dumps(rr[0], indent=4))


def getReportId(report_id):
    q = {}
    q["report_ids"] = report_id
    response = requests.get(report_url, params=q, headers = headers)
    return json.loads(response.text)


def getScanId(scan_id):
    q = {}
    q["scan_ids"] = scan_id
    response = requests.get(scan_url, params=q, headers = headers)
    return json.loads(response.text)


def makeAsyncReqResp(chats):
    print()
    print("Async requests")
    reqs = []
    for chat in chats:
        req = {}
        req["req_id"] = len(reqs)
        req["scan_req"] = dict(base_req)
        req["scan_req"]["contents"] = chats[chat]
        req["scan_req"]["tr_id"] = chat
        reqs.append(req)
    print(reqs)
    response = requests.post(async_url, json=reqs, headers = headers)
    json_data = json.loads(response.text)
    print("Response: ")
    print(json_data)
    if "error" in json_data:
        exit(1)
    report_id = json_data["report_id"]

    print()
    print("Async scan result")
    scan_id = json_data["scan_id"]
    for count in range(50):
        time.sleep(0.5)
        json_data = getScanId(scan_id)
        print(count)
        if "error" in json_data:
            print("error found")
            print(json.dumps(json_data, indent=4))
            exit(1)
        if all((v["status"]=="complete") for _,v in enumerate(json_data)):
            print("All complete")
            break
    else:
        print("Waited long enough, moving on...")

    print()
    print("Async scan report")
    rr = getReportId(report_id)
    print(json.dumps(rr, indent=4))


def preparations(args):
    global headers
    if os.getenv("aipantoken"):
        headers['x-pan-token'] = os.getenv("aipantoken")
    else:
        print("No xpantoken env present")
    if os.getenv("aiprofilename"):
        base_req["ai_profile"]["profile_name"] = os.getenv("aiprofilename")


if __name__ == "__main__":
    chats = {}
    try:
        import chats_basic
        chats_basic.add_chats_basic(chats)
        import chats_extra
        chats_extra.add_chats_extra(chats)
    except:
        pass

    parser = argparse.ArgumentParser()
    parser.add_argument('--chat', nargs='?', action='store')
    parser.add_argument('--profile-name', nargs='?', action='store')
    parser.add_argument('--report-id', nargs='?', action='store')
    parser.add_argument('--report', action='store_true')
    parser.add_argument('--scan-id', nargs='?', action='store')
    parser.add_argument('--sync', action='store_true')
    args = parser.parse_args()

    preparations(args)

    if args.profile_name:
        base_req["ai_profile"]["profile_name"] = args.profile_name
    if args.report_id:
        rr = getReportId(args.report_id)
        print(json.dumps(rr, indent=4))
        exit()
    if args.scan_id:
        sr = getScanId(args.scan_id)
        print(json.dumps(sr, indent=4))
        exit()

    if base_req["ai_profile"]["profile_name"]=="":
        print("Provie profile-name or export aiprofilename env")

    if args.chat:
        for c in list(chats.keys()):
            if c!=args.chat:
                chats.pop(c)

    print(chats)

    if args.chat or args.sync:
        makeSyncRequest(chats, args.report)
        exit()

    if not args.chat:
        makeAsyncReqResp(chats)
        exit()

    print("We should not end up here")
