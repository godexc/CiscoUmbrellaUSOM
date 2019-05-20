# Cisco Umbrella USOM
USOM (National SOC of Turkey) Integration with Cisco Umbrella as an Intelligence Source.

# Requirements
- Python 3.x
- Json, Requests and Time
- You need to change customer_key= #YOUR CUSTOMER KEY CAN BE FOUND UNDER THE Policies -> Integrations " umbrella_usom.py

# What it does?
- It looks up to the site "https://www.usom.gov.tr/url-list.txt" parses the URLs and pushes them to your Cisco Umbrella Account via Enforcement API.

- SafeGuards are disabled so be aware of the list you are using as it can block a non-malicious Website.

- Maximum 50 Calls Per minute, it might take a while before you finish the whole list. 

 - Domain checks are added in order to avoid multiple calls for the same domain.

- Call it using python umbrella_usom.py or with >> output.txt
 
 # Feature Enchancements
 
 - Logging will be added.
 

