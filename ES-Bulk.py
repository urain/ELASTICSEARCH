# This script is for parsing SNORT community rules and adding them to ELASTICSEARCH in bulk.

import re
import json
import time
import requests

# sudo sysctl -w vm.max_map_count=262144
# sudo docker run -p 5601:5601 -p 9200:9200 -p 5044:5044 -it --name elk sebp/elk       (to make new container named elk)
# sudo docker start|stop|restart elk
# sudo docker rm elk

jsonOutput = open("snort.json","wb")
with open("community.txt","r") as f:
	content = f.readlines()
content = [x[2:].strip() for x in content]

for line in content:
	if line == "" or line == "\n":
		continue
	res = re.search(r'(^.+)\((.+)\)',line)
	#make dict
	header = res.groups(1)[0]
	option = res.groups(1)[1]	   
	#process the header by splitting on space
	headers = header.split()

	rule = {
			'action':headers[0],
			'protocol':headers[1],
			'srcaddresses':headers[2],
			'srcports':headers[3],
			'direction':headers[4],
			'dstaddresses':headers[5],
			'dstports':headers[6],
			'activatedynamic':"none"				  
			}
	#attribute/value pairs
	ruleOptions = {}
	options = option.split(";")
	for opt in options:
		try:
			kv = opt.split(":")
			ruleOptions[kv[0].strip()] = kv[1]
		except Exception:
			pass
	rule['options'] = ruleOptions

	# required header before every json line we will index
	jsonOutput.write("{\"index\" : { \"_index\" : \"snort\", \"_type\" : \"rules\" } }\n")
	json.dump(rule, jsonOutput)
	jsonOutput.write("\n")
	
# Bulk indexing data	
rule = open("snort.json","rb").read()
headers = {'Content-type': 'application/x-ndjson', 'Accept': 'text/plain'}
r = requests.post("http://192.168.19.161:9200/snort/rules/_bulk", data=rule, headers=headers)
