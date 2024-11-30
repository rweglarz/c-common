import argparse, json, os, requests, time

sync_url   = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"
async_url  = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/async/request"
scan_url   = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/results"
report_url = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/reports"

profile_name = "rwe-airs-api-20241118-allow-all-1"

headers = {
    'x-pan-token': 'fill it in or use xpantoken env value',
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

base_req = {
    "ai_profile": {
        "profile_name": profile_name
    }
}



def makeSyncRequest(chats):
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


def printReportId(report_id):
    q = {}
    q["report_ids"] = report_id
    response = requests.get(report_url, params=q, headers = headers)
    json_data = json.loads(response.text)
    print(json.dumps(json_data, indent=4))


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
    report_id = json_data["report_id"]
    print("Response: ")
    print(json_data)
    if "error" in json_data:
        exit(1)

    print()
    print("Async scan result")
    q = {}
    q["scan_ids"] = json_data["scan_id"]
    for count in range(50):
        time.sleep(0.5)
        response = requests.get(scan_url, params=q, headers = headers)
        json_data = json.loads(response.text)
        print(count)
        if count==0:
            print(json.dumps(json_data, indent=4))
        if all((v["status"]=="complete") for _,v in enumerate(json_data)):
            print("All complete")
            if count>0:
              print(json.dumps(json_data, indent=4))
            break
        print(".")
    else:
        print("Waited long enough, moving on...")

    print()
    print("Async scan report")
    printReportId(report_id)


def preparations():
    global headers
    if os.getenv("xpantoken"):
        headers['x-pan-token'] = os.getenv("xpantoken")
    else:
        print("No xpantoken env present")



if __name__ == "__main__":
    chats = {}
    preparations()
    try:
        import chats_basic
        chats_basic.add_chats_basic(chats)
        import chats_extra
        chats_extra.add_chats_extra(chats)
    except:
        pass

    parser = argparse.ArgumentParser()
    parser.add_argument('--report-id', nargs='?', action='store')
    args = parser.parse_args()

    if args.report_id:
        printReportId(args.report_id)
        exit()

    print(chats)
    makeSyncRequest(chats)
    makeAsyncReqResp(chats)
