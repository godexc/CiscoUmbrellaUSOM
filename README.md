# CiscoUmbrellaUSOM
USOM (National SOC of Turkey) Integration with Cisco Umbrella as an Intelligence Source

What it does?
-It looks up to the site "https://www.usom.gov.tr/url-list.txt" parses the URLs and pushes them to your Cisco Umbrella Account via Enforcement API.
-SafeGuards are disabled so be aware of the list you are using as it can block a non-malicious Website.

You need to change
customer_key= #YOUR CUSTOMER KEY CAN BE FOUND UNDER THE Policies -> Integrations " umbrella_usom.py
