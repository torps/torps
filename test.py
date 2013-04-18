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

##### Find top exit and guard consensus bandwidths #####
in_dir = 'out/new/ns-2012-03-02--04'
pathnames = []
for dirpath, dirnames, fnames in os.walk(in_dir):
    for fname in fnames:
        pathnames.append(os.path.join(dirpath,fname))
pathnames.sort()

relays = {}

for pathname in pathnames:
    with open(pathname) as f:
        consensus = pickle.load(f)
        descriptors = pickle.load(nsf)

    for fprint, relay in consensus.relays.items():
        if (fprint in descriptors):
            desc = descriptors[fprint]
            if (fprint not in relays):
                relays[fprint] = {'nickname':relay.nickname,\
                    'fingerprint':fprint,\
                    'bandwidth':relay.bandwidth,\
                    'average_bandwidth':desc.average_bandwidth,\
                    'burst_bandwidth':desc.burst_bandwidth,\
                    'observed_bandwidth':desc.observed_bandwidth)]
            else:
                relays[fprint].append((relay.bandwidth,\
                    desc.average_bandwidth, desc.burst_bandwidth,\
                    desc.observed_bandwidth))
            self.bandwidth = bandwidth
                    
        self.average_bandwidth = average_bandwidth
        self.burst_bandwidth = burst_bandwidth
        self.observed_bandwidth = observed_bandwidth 
class RouterStatusEntry:
    """
    Represents a relay entry in a consensus document.
    Trim version of stem.descriptor.router_status_entry.RouterStatusEntry.
    """
    def __init__(self, fingerprint, nickname, flags, bandwidth, address,\
        or_port, exit_policy):
        self.fingerprint = fingerprint
        self.nickname = nickname
        self.flags = flags
        self.bandwidth = bandwidth
        
        # not currently used, but potentially useful
        self.address = address # IP address in consensus
        self.or_port = or_port
        self.exit_policy = exit_policy # micro exit policy
    

class NetworkStatusDocument:
    """
    Represents a consensus document.
    Trim version of stem.descriptor.networkstatus.NetworkStatusDocument.
    """
    def __init__(self, valid_after, fresh_until, bandwidth_weights, \
        bwweightscale, relays, is_microdescriptor):
        self.valid_after = valid_after
        self.fresh_until = fresh_until
        self.bandwidth_weights = bandwidth_weights
        self.bwweightscale = bwweightscale
        self.relays = relays
        
        # not currently used, but potentially useful
        self.is_microdescriptor = is_microdescriptor


class ServerDescriptor:
    """
    Represents a server descriptor.
    Trim version of stem.descriptor.server_descriptor.ServerDescriptor.
    """
    def __init__(self, fingerprint, hibernating, nickname, family, address,\
        exit_policy, or_port, uptime, average_bandwidth, burst_bandwidth,\
        observed_bandwidth):
        self.fingerprint = fingerprint
        self.hibernating = hibernating
        self.nickname = nickname
        self.family = family
        self.address = address
        self.exit_policy = exit_policy
        
        # not currently used, but potentially useful
        self.or_port = or_port
        self.uptime = uptime
        self.average_bandwidth = average_bandwidth
        self.burst_bandwidth = burst_bandwidth
        self.observed_bandwidth = observed_bandwidth            
##########        