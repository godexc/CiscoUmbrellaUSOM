#CCO ID: hevyapan Umbrella Enforcement API Integration with USOM Malicious Connections

from datetime import datetime
import time
import json
import requests

customer_key= #YOUR CUSTOMER KEY CAN BE FOUND UNDER THE Policies -> Integrations "
requests.packages.urllib3.disable_warnings()
url_events="https://s-platform.api.opendns.com/1.0/events?customerKey="+customer_key
url_domains="https://s-platform.api.opendns.com/1.0/domains?customerKey="+customer_key
headers = {'Content-Type': 'application/json'}
dictList =[]
Enf_Obj = dict()

Enf_Obj["alertTime"] = datetime.now().isoformat(timespec='seconds')+'Z'
Enf_Obj["deviceId"] = "ba6a59f4-e692-4724-ba36-c28132c761de"
Enf_Obj["deviceVersion"] ="13.7a"
Enf_Obj["eventTime"] = datetime.now().isoformat(timespec='seconds')+'Z'
Enf_Obj["protocolVersion"] = "1.0a"
Enf_Obj["providerName"] = "Security Platform"
Enf_Obj["disableDstSafeguards"] = True
a = requests.get("https://www.usom.gov.tr/url-list.txt", stream = True)

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
        dictList.append(Enf_Obj.copy())

for enf_dict in dictList:
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

#Check the domains if it is in the list already
#inc_domains = requests.get(url_domains, verify=False, headers=headers)
#inc_domains = inc_domains.text
#json_inc_domains = json.loads(inc_domains)









