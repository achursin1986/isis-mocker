#!/usr/bin/env python3

'''
replaces hostnames with sysid in show isis db json output
looks ugly and terrifying, but works
'''

import os
import json
import re
import collections
from argparse import ArgumentParser
from pathvalidate.argparse import validate_filename_arg, validate_filepath_arg

parser = ArgumentParser()
parser.add_argument("--filepath", type=validate_filepath_arg, help="work dir")
parser.add_argument("--sourcedb", type=validate_filename_arg, help="source isis database json")
parser.add_argument("--hosts", type=validate_filename_arg, help="hosts isis database file")
parser.add_argument("--output", type=validate_filename_arg, help="ready isis database file")
options = parser.parse_args()

os.environ["PYTHONIOENCODING"] = "utf-8"

dir=options.filepath
outfile=options.output
os.chdir(dir)

hostsfile=open(dir + "/" + options.hosts)

isishostsjson = json.loads(hostsfile.read())
hostsfile.close

def nodupsanymore(op):
  count=0
  d=collections.OrderedDict()
  for k,v in op:
      if k in d:
          d[k+str(count)]=v
          count+=1
      else:
          d[k]=v
  return d

dbfile=open(dir + "/" + options.sourcedb)
isisdbjson = json.loads(dbfile.read(),object_pairs_hook=nodupsanymore)
dbfile.close

hostsdict={}
for k in isishostsjson["isis-hostname-information"][0]["isis-hostname"]:
    rsysid=k["system-id"][0]["data"]
    rhostname0=k["system-name"][0]["data"]
    rhostname=rhostname0.split(".00-")[0]
    hostsdict[rhostname]=rsysid
for n in isisdbjson["isis-database-information"][0]["isis-database"]:
    if n["level"][0]["data"] in ["1", "2"]:
        for m in n["isis-database-entry"]:
            lspid = m["lsp-id"][0]["data"]
            lspidsplitted = lspid.split(".00-")[0]
            lspfragidsplitted = lspid.split(".00-")[1]
            for x in hostsdict:
                if x == lspidsplitted:
                    m["lsp-id"][0]["data"] = hostsdict[x] + ".00-" + lspfragidsplitted
            if "isis-tlv" in m:
                reachabilitylist=[]
                for member in m["isis-tlv"][0]:
                    if re.match("reachability-tlv\d", member):
                        reachabilitylist.append(member)
                if len(reachabilitylist) > 0:
                    for mem in reachabilitylist:
                        for y11 in m["isis-tlv"][0][mem]:
                            initaddrprefix1 = y11["address-prefix"][0]["data"]
                            for x21 in hostsdict:
                                if x21 + ".00" == initaddrprefix1:
                                    y11["address-prefix"][0]["data"] = hostsdict[x21] + ".00"
                if "reachability-tlv" in m["isis-tlv"][0]:
                    for y1 in m["isis-tlv"][0]["reachability-tlv"]:
                        if isinstance(y1, list):
                            for y24 in y1:
                                initaddrprefix24 = y24["address-prefix"][0]["data"]
                                for x24 in hostsdict:
                                    if x24 + ".00" == initaddrprefix24:
                                        y24["address-prefix"][0]["data"] = hostsdict[x24] + ".00"
                        else:
                            initaddrprefix = y1["address-prefix"][0]["data"]
                            for x2 in hostsdict:
                                if x2 + ".00" == initaddrprefix:
                                    y1["address-prefix"][0]["data"] = hostsdict[x2] + ".00"

            if "lsp-id" in m:
                initpktlspid = m["lsp-id"][0]["data"].split(".00-")[0]
                initpktlspfrag = m["lsp-id"][0]["data"].split(".00-")[1]
                for x31 in hostsdict:
                    if x31 == initpktlspid:
                        m["lsp-id"][0]["data"] = hostsdict[x31] + ".00-" + initpktlspfrag

with open(outfile, "w") as outdata:
    json.dump(isisdbjson, outdata)
