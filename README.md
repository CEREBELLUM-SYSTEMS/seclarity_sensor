# seclarity_sensor
Simple Python scripts for parsing network traffic. Utilizing Scapy and Scapy-HTTP to sniff packets and parse specific pieces of data from DHCP and HTTP packets to identify the type of device. 

## Requirements
* Scapy - https://pypi.org/project/scapy/
* Scapy-HTTP - https://github.com/invernizzi/scapy-http
* pymongo - https://api.mongodb.com/python/current/

## Usage
### dhcp_parse
Monitor for DHCP traffic and extract hostname, parameter request list and vendor id. Once identified and extracted its added to MongoDB. MAC address is identifier.

### http_parse
Monitor HTTP traffic and extract HTTP-USER-AGENT strings. Once identified and extracted added to MongoDB via addToSet. There is likely some kind of memory leak in Scapy-HTTP or in my code as running this script eventually stalls after roughly a day and needs to killed and restarted. 

### So What?
Now that you have this information you can easily query https://fingerbank.org for the device classification. 