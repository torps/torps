##### Aggregate relays that appear in consensus with descriptor 4/12-3/13 #####

## if using in pypy, i needed this first so it would grab networkx and stem correctly
## export PYTHONPATH=/usr/lib/python2.7/site-packages/:/home/rob/research/orsec/stem-install/lib/python2.7/site-packages

import json
import cPickle as pickle
from pathsim import *
#from networkx import Graph
from itertools import product
from time import time

in_dir = 'network-state-2012-04--2013-03'
out_file = 'relaypairs2.2012-04--2013-03.json'

network_state_files = []
for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
    for filename in filenames:
        if (filename[0] != '.'):
            network_state_files.append(os.path.join(dirpath,filename))

# aggregate relays in consensuses with descriptors
g = {}#Graph()
network_state_files.sort(key = lambda x: os.path.basename(x), reverse=True)
nsf_len = len(network_state_files)
nsf_i = 0
start = time()
lapstamp = start
lapstotal, lapslen = 0.0, 0
chkpntend = os.path.basename(network_state_files[0])[0:10]
for ns_file in network_state_files:
    fname = os.path.basename(ns_file)
    stamp = time()
    lapstotal += (stamp-lapstamp)
    lapslen += 1
    lapstamp = stamp

    # print progress information
    sys.stdout.write('\r[{1}/{2}][{0}%][hr elap. {3}][hr rem. {4}]: {5}'.format("%.3f" % (nsf_i * 100.0 / nsf_len), nsf_i+1, nsf_len, "%.3f" % ((stamp-start)/3600.0), "%.3f" % ((lapstotal/lapslen)*(nsf_len-nsf_i)/3600.0), fname))
    sys.stdout.flush()

    with open(ns_file, 'rb') as nsf:
        consensus = pickle.load(nsf)
        descriptors = pickle.load(nsf)

    ips = {}
    # filter all relays in this consensus to those that
    # have a descriptor, are running, and are fast
    for relay in consensus.relays:
        if (relay in descriptors):
            sd = descriptors[relay] # server descriptor
            rse = consensus.relays[relay] # router status entry
            if "Running" in rse.flags and "Fast" in rse.flags:
                if relay not in ips: ips[relay] = []
                ips[relay].append(sd.address)
    # build edges between every relay that could have been
    # selected in a path together
    for r1 in ips:
        for r2 in ips:
            if r1 is r2: continue
            pairs = product(ips[r1], ips[r2])
            for (ip1, ip2) in pairs:
                if ip1 < ip2: g["{0}-{1}".format(ip1,ip2)] = True
                else: g["{0}-{1}".format(ip2,ip1)] = True
    nsf_i += 1
    # check if we should do a checkpoint and save our progress
    if nsf_i == nsf_len or "01-00-00-00" in fname:
        chkpntstart = fname[0:10]
        with open("relaypairs2.{0}--{1}.json".format(chkpntstart, chkpntend), 'wb') as f: json.dump([k.split('-') for k in g], f)

print ""
#print('Num addresses: {0}'.format(g.number_of_nodes()))
print('Num unique pairs: {0}'.format(len(g)))

# write final graph to disk
with open(out_file, 'wb') as f: json.dump([k.split('-') for k in g], f)
##########

