# useful code fragments for testing path simulator (pathsim.py)

import stem.descriptor.reader as sdr
import datetime
import os
import os.path
import stem.descriptor as sd
import stem.descriptor.networkstatus as sdn
import stem
import random
import sys
import collections
import pathsim

def timestamp(t):
    """Returns UNIX timestamp"""
    td = t - datetime.datetime(1970, 1, 1)
    ts = td.days*24*60*60 + td.seconds
    return ts

### read in consensuses and (old-style) processed descriptors ###
r_file = 'in/cons-2012-08-02-00/2012-08-02-00-00-00-consensus'
d_file = 'out/desc-2012-08-02-00/2012-08-02-00-00-00-descriptor'
descriptors = {}

cur_period_start = None
cur_period_end = None

cons_valid_after = None
cons_fresh_until = None
cons_bw_weights = None
cons_bwweightscale = None        
cons_rel_stats = {}

with open(d_file, 'r') as df:
    for desc in sd.parse_file(df, validate=False):
        descriptors[desc.fingerprint] = desc
with open(r_file, 'r') as cf:        
    for rel_stat in sd.parse_file(cf, validate=False):
        cons_valid_after = \
            timestamp(rel_stat.document.valid_after)
        cur_period_start = cons_valid_after
        cons_fresh_until = \
            timestamp(rel_stat.document.fresh_until)
        cur_period_end = cons_fresh_until
        cons_bw_weights = rel_stat.document.bandwidth_weights
        if ('bwweightscale' in rel_stat.document.params):
            cons_bwweightscale = rel_stat.document.params[\
                'bwweightscale']
        else:
            cons_bwweightscale = 10000  
        if (rel_stat.fingerprint in descriptors):
            cons_rel_stats[rel_stat.fingerprint] = rel_stat
######

### read in all descriptors from a month ###
sd_dir = 'in/server-descriptors-2012-08'
num_descriptors = 0    
num_relays = 0
all_descriptors = {}
with sdr.DescriptorReader(sd_dir, validate=True) as reader:
    for desc in reader:
        if (num_descriptors % 10000 == 0):
            print('{0} descriptors processed.'.format(num_descriptors))
        num_descriptors += 1
        if (desc.fingerprint not in all_descriptors):
            all_descriptors[desc.fingerprint] = {}
            num_relays += 1
        all_descriptors[desc.fingerprint][timestamp(desc.published)] = desc
print('#descriptors: {0}; #relays:{1}'.\
    format(num_descriptors,num_relays)) 
######

#### go through hibernate statuses for a given relay in all_descriptors ###
fprint = 'BC77196F4730442A96E36E1A13B3FF8DC14151EB' # RememberJobs
descs = all_descriptors[fprint]
desc_times = sorted(descs.keys())
for t in desc_times:
    print('{0} ({1}): {2}'.format(descs[t].published.strftime('%Y-%m-%d %H:%M:%S'), t, descs[t].hibernating))
######

###### look for hibernating statuses of a given relay ######
fprint = 'FD688C0692D87AC0D04D42FF4C606FF1AB420C9E'
for hs in hibernating_statuses:
    if (hs[1] == fprint):
        print(hs)
######


##### Aggregate relays that appear in consensus with descriptor 3/12-3/13 #####
import json
import pickle
from pathsim import *
in_dir = 'out/network-state-2012-03--2013-03'
#in_dir = 'network-state-2012-03--04'
out_file = 'out/relays.2012-03--2013--03.json'
#out_file = 'relays.2012-03--04.json'
network_state_files = []
for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
    for filename in filenames:
        if (filename[0] != '.'):
            network_state_files.append(os.path.join(dirpath,filename))

# aggregate relays in consensuses with descriptors
relays = {}
network_state_files.sort(key = lambda x: os.path.basename(x))
num_addresses = 0
for ns_file in network_state_files:
    print('Reading {0}'.format(os.path.basename(ns_file)))
    with open(ns_file, 'r') as nsf:
        consensus = pickle.load(nsf)
        descriptors = pickle.load(nsf)
    for relay in consensus.relays:
        if (relay in descriptors):
            if relay in relays:
                if (descriptors[relay].address not in relays[relay]['a']):
                    relays[relay]['a'].append(descriptors[relay].address)
                    num_addresses += 1                    
            else:
                relays[relay] = {\
                    'n':consensus.relays[relay].nickname,\
                    'f':consensus.relays[relay].fingerprint,\
                    'a':[descriptors[relay].address],\
                    'r':True}
                num_addresses += 1
print('Num relays: {0}'.format(len(relays)))
print('Num addresses: {0}'.format(num_addresses))

# turn relays dict into {'relays':[relay dict]} and write to disk
relays_list = []
for rel_fp, rel_dict in relays.items():
    relays_list.append(rel_dict)
relays_out = {'relays':relays_list}
with open(out_file, 'w') as f:
    json.dump(relays_out, f, indent=4)
# {"relays":[
# {"n":"PelmenTorRelay","f":"3CE26C7E299224F958BBC6BF76101CD2AF42CEDE","a":["2.93.158.149"],"r":false},
# {"n":"darwinfish","f":"9DD5F90D641D835C4FCA7153148B156E6FD49CEE","a":["46.4.106.18"],"r":true}
# ]
# }                
##########

##### Examine user traces #####
# "facebook"
# "gmailgchat"
# "gcalgdocs"
# "websearch"
# "irc"
# "bittorrent"

tracefile = 'in/traces.pickle'
tracename = 'bittorrent'

#streams =   get_user_model(start_time, end_time, 'in/traces.pickle', tracename)

f = open(tracefile)
obj = pickle.load(f)
f.close()

streams = obj.trace[tracename]

# ips and ports
ips = set()
ports = set()
for stream in streams:
    ips.add(stream[1])
    ports.add(stream[2])
    
# streams to .exit
exit_ip_streams = []
for stream in streams:
    if ('.exit' in stream[1]):
        exit_ip_streams.append(stream)

# ips to .exit
exit_ips = []
for ip in ips:
    if ('.exit' in ip):
        exit_ips.append(ip)
        
# streams to 9001
or_port_streams = []
for stream in streams:
    if (9001 == stream[2]):
        or_port_streams.append(stream)
# streams to 9001 but not to a .exit
or_port_nonexit_streams = []
for stream in streams:
    if (9001 == stream[2]) and\
        ('.exit' not in stream[1]):
        or_port_nonexit_streams.append(stream)
        
# print streams
for stream in streams:
    print('[{0:.1f}]\t{1}:{2}'.format(stream[0], stream[1], stream[2]))

# remove streams that duplicate an ip/24:port seen 10 minutes ago
max_circuit_dirtiness = 10*60
cover_time = float(max_circuit_dirtiness)/2
ip_port_seen = {}
streams_reduced = []
for stream in streams:
    ip_split = stream[1].split('.')
    ip_24 = '.'.join(ip_split[0:3])
    ip_port = ip_24 + ':' + str(stream[2])
    if (ip_port in ip_port_seen) and\
        (stream[0] - ip_port_seen[ip_port] < cover_time):
        continue
    else:
        ip_port_seen[ip_port] = stream[0]
        streams_reduced.append(stream)

### Results ###
#start_time: 1330646400
#end_time: 1335830399

#facebook
# num streams 3/12-4/12: 107081=1755.4/day
# num streams reduced (5 min. window, /24): 47
# num streams in trace: 637
# num streams to .exit: 4
# num streams to 9001 but not .exit: 0
# ips
  # num: 91
  # num w/ .exit: 4
# ports
  # num: 3
  # [80, 9001, 443]
  # to non-exit: [80, 443]
  
#gmailgchat
# num streams in trace: 516
# num streams to .exit: 0
# num streams reduced (5 min. window, /24): 40
# ips
    # num: 70
# ports
  # num: 2
  # [80, 443]
  
#gcalgdocs
# num streams in trace: 370
# num streams to .exit: 0
# num streams reduced (5 min. window, /24): 17
# ips
    # num: 42
# ports
  # num: 2
  # [80, 443]  
  
#websearch
# num streams in trace: 1343
# num streams to .exit: 0
# num streams reduced (5 min. window, /24): 138
# ips
    # num: 170
# ports
  # num: 2
  # [80, 443] 
  
#irc
# num streams in trace: 1
# num streams to .exit: 0
# ips
    # num: 1
# ports
  # num: 1
  # [6697]  
     
#bittorrent
# num streams in trace: 355
# num streams to .exit: 4
# num streams to 9001 but not .exit: 0
# num streams reduced (5 min. window, /24): 321
# ips
    # num: 285
# ports
  # num: 164  
  
  
# Model streams / week
# simple: 1008
# fb: 47*4*5 = 940
# websearch: 138*4*5 = 2760
# bittorrent: 321*18*7 = 40446
#  OR 321*18*2 = 11556  
# typical (fb+gmail+gcalgdocs) = (47 + 40 + 17)*4*5 = 2080     
###### 
##########

##### Process traces #####

# Turn trace streams with destination ip *.exit into resolve requests
# Filter out requests to same /24 and port within max_circuit_dirtiness/2
from pathsim import *
import cPickle as pickle
in_tracefile = 'in/traces.pickle'
out_tracefile = 'in/traces_processed.pickle'
with open(in_tracefile) as f:
    obj = pickle.load(f)

models = ["facebook" , "gmailgchat", "gcalgdocs", "websearch", "irc",\
    "bittorrent"]
max_circuit_dirtiness = 10*60
cover_time = float(max_circuit_dirtiness)/2
for key in models:
    model_trace = obj.trace[key]
    new_model_trace = []
    ip_port_seen = {}
    for stream in model_trace:
        if ('.exit' not in stream[1]):
            # remove streams that duplicate an ip/24:port seen recently
            ip_split = stream[1].split('.')
            ip_24 = '.'.join(ip_split[0:3])
            ip_port = ip_24 + ':' + str(stream[2])
            if (ip_port in ip_port_seen) and\
                (stream[0] - ip_port_seen[ip_port] < cover_time):
                continue
            else:
                ip_port_seen[ip_port] = stream[0]
                new_model_trace.append(stream)
        else:
            ip_split = stream[1].split('.')
            new_ip = '.'.join(ip_split[0:4])
            new_model_trace.append((stream[0], new_ip, 0))
    obj.trace[key] = new_model_trace

with open(out_tracefile, 'wb') as f:
    pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)
##########    