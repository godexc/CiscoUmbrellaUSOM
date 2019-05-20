#!/usr/bin/env python3

#CCO ID: hevyapan Umbrella Enforcement API Integration with USOM Malicious Connections

'''

 _   _           _              _ _         _   _ ____   ___  __  __
| | | |_ __ ___ | |__  _ __ ___| | | __ _  | | | / ___| / _ \|  \/  |
| | | | '_ ` _ \| '_ \| '__/ _ \ | |/ _` | | | | \___ \| | | | |\/| |
| |_| | | | | | | |_) | | |  __/ | | (_| | | |_| |___) | |_| | |  | |
 \___/|_| |_| |_|_.__/|_|  \___|_|_|\__,_|  \___/|____/ \___/|_|  |_|

 _____        __                                         _
| ____|_ __  / _| ___  _ __ ___ ___ _ __ ___   ___ _ __ | |_
|  _| | '_ \| |_ / _ \| '__/ __/ _ \ '_ ` _ \ / _ \ '_ \| __|
| |___| | | |  _| (_) | | | (_|  __/ | | | | |  __/ | | | |_
|_____|_| |_|_|  \___/|_|  \___\___|_| |_| |_|\___|_| |_|\__|


'''


from datetime import datetime
import time
import json
import requests


customer_key= #YOUR CUSTOMER KEY CAN BE FOUND UNDER THE Policies -> Integrations "
requests.packages.urllib3.disable_warnings()
url_events="https://s-platform.api.opendns.com/1.0/events?customerKey="+customer_key
url_domains="https://s-platform.api.opendns.com/1.0/domains?customerKey="+customer_key
headers = {'Content-Type': 'application/json'}
dictList =[] # LIST OF DICTIONARIES
Enf_Obj = dict() # OBJECTS THAT WILL BE USED IN ENFORCEMENT API
in_place_domain_list = [] # FOR DOMAINS ALREADY IN UMBRELLA

Enf_Obj["alertTime"] = datetime.now().isoformat(timespec='seconds')+'Z'
Enf_Obj["deviceId"] = "ba6a59f4-e692-4724-ba36-c28132c761de"
Enf_Obj["deviceVersion"] ="13.7a"
Enf_Obj["eventTime"] = datetime.now().isoformat(timespec='seconds')+'Z'
Enf_Obj["protocolVersion"] = "1.0a"
Enf_Obj["providerName"] = "Security Platform"
Enf_Obj["disableDstSafeguards"] = True

a = requests.get("https://www.usom.gov.tr/url-list.txt", stream = True)

# GET DATA AND CREATE THE LIST OF DOMAINS WHICH ARE ALREADY BEEN INCLUDED IN UMBRELLA
while True:
    r = requests.get(url_domains, headers=headers, verify=False)
    status_code=r.status_code
    resp=r.text
    json_resp = json.loads(resp)
    for domain in json_resp['data']:
        in_place_domain_list.append((domain['name']))
    if json_resp['meta']['next'] != False:
        url_domains = json_resp['meta']['next']
    else:
        break

# GET DATA AND CREATE THE LIST OF DICTIONARIES FOR API POST
for line in a.iter_lines():
    if line :
        string_line = line.decode('ASCII')
        if "/" not in string_line:
            Enf_Obj["dstDomain"] = string_line
            Enf_Obj["dstUrl"] = "http://"+string_line+"/"
        if "/" in string_line:
            if "http" in string_line:
                Enf_Obj["dstDomain"] = string_line.split("/")[2]
                Enf_Obj["dstUrl"] = string_line
        #COMPARE WITH THE DATA ALREADY INCLUDED
        if Enf_Obj["dstDomain"] not in in_place_domain_list:
            dictList.append(Enf_Obj.copy())

# START POSTING DATA VIA THE API TO UMBRELLA
for enf_dict in dictList:
    print(enf_dict["dstUrl"])
    json_enf_obj = json.dumps(enf_dict, indent=3 )
    time.sleep(1.5)
    try:
        r = requests.post(url_events, data=json_enf_obj, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        print("Status code is: " + str(status_code))
        if status_code == 201 or status_code == 202:
            print("Post was successful...")
            json_resp = json.loads(resp)
            print(json.dumps(json_resp, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            r.raise_for_status()
            print("Error occurred in POST --> " + resp)
    except requests.exceptions.HTTPError as err:
        print("Error in connection --> " + str(err))
    finally:
        if r: r.close()

