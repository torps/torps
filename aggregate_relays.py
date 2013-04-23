##### Aggregate relays that appear in consensus with descriptor 4/12-3/13 #####
import json
import cPickle as pickle
from pathsim import *
import networkx, itertools

in_dir = 'network-state-2012-04--2013-03'
out_file = 'relaypairs.2012-04--2013-03.json'

network_state_files = []
for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
    for filename in filenames:
        if (filename[0] != '.'):
            network_state_files.append(os.path.join(dirpath,filename))

# aggregate relays in consensuses with descriptors
g = networkx.Graph()
network_state_files.sort(key = lambda x: os.path.basename(x))
nsf_len = len(network_state_files)
nsf_i = 0
for ns_file in network_state_files:
    sys.stdout.write('\rProgress {0}% ({1} of {2}): processing {3}'.format((nsf_i * 100 / nsf_len), nsf_i+1, nsf_len, os.path.basename(ns_file)))
    sys.stdout.flush()

    with open(ns_file, 'rb') as nsf:
        consensus = pickle.load(nsf)
        descriptors = pickle.load(nsf)

    ips = {}
    for relay in consensus.relays:
        if (relay in descriptors):
            sd = descriptors[relay] # server descriptor
            rse = consensus.relays[relay] # router status entry
            if "Running" in rse.flags and "Fast" in rse.flags:
                if relay not in ips: ips[relay] = []
                ips[relay].append(sd.address)
    for r1 in ips:
        for r2 in ips:
            if r1 is r2: continue
            g.add_edges_from(itertools.product(ips[r1], ips[r2]))                    
    nsf_i += 1

print ""
print('Num addresses: {0}'.format(g.number_of_nodes()))
print('Num unique pairs: {0}'.format(g.number_of_edges()))

# write to disk
with open(out_file, 'wb') as f: json.dump(g.edges(), f)
##########
