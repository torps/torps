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
