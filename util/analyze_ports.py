#!/usr/bin/python

"""
Looks through network state files to find the ports that both the
most and fewest exits allow. If SCANALLPORTS, then every possible
port is scanned for each relay, but only for the first consensus
of each day. Otherwise, a common subset is scanned for all relays
for every consensus. Status for each consensus is printed to stdout,
and a dict showing counts for the number of exits accepting each
port is pickled to analyze_consensus_output/ dir for each consensus.
"""
import os, sys, stem
from pathsim import *

SCANALLPORTS=True
OUTDIR = "portscan_all_output" if SCANALLPORTS else "portscan_subset_output"

##########

if len(sys.argv) != 2: print "USAGE: {0} network_state_directory".format(sys.argv[0]);sys.exit()
if not os.path.exists(OUTDIR): os.mkdir(OUTDIR)

allports = [i+1 for i in xrange(65535)]
longlivedports = [21, 22, 706, 1863, 5050, 5190, 5222, 5223, 6523, 6667, 6697, 8300]
defaultexitpolicy = stem.exit_policy.ExitPolicy("reject *:25", "reject *:119", "reject *:135-139", "reject *:445", "reject *:563", "reject *:1214", "reject *:4661-4666", "reject *:6346-6429", "reject *:6699", "reject *:6881-6999", "accept *:*")

# check this subset
ports = allports if SCANALLPORTS else [21, 22, 25, 80, 443, 6699, 8080, 9000, 9001]

def main():
    nsfs = get_network_state_files(sys.argv[1])
    for nsf in nsfs:
        result = process_nsf(nsf, dump=True)
        if result is not None: print result

def process_nsf(nsf, dump=False):
    numexits = {} # port:counter for number of relays that exit to port
    totalallowed, donecounting = 0, False
    base = os.path.basename(nsf)
    consensus, descriptors = load_data(nsf)

    t = consensus.valid_after.isoformat()
    if SCANALLPORTS and "T00:00:00" not in t: return None

    for p in ports:
        if not defaultexitpolicy.can_exit_to(port=p, strict=True): continue
        numexits[p] = 0
        needstable = p in longlivedports
        for relay in consensus.relays:
            if relay in descriptors: 
                rse = consensus.relays[relay] # router status entry
                sd = descriptors[relay] # server descriptor
                if not donecounting and sd.exit_policy.is_exiting_allowed(): totalallowed += 1
                canexit = sd.exit_policy.can_exit_to(port=p, strict=True)
                if canexit and (not needstable or (needstable and "Stable" in rse.flags)): numexits[p] += 1
        donecounting = True
    maxport = max(numexits, key=lambda x:numexits[x])
    minport = min(numexits, key=lambda x:numexits[x])

    if dump:
        with open("{0}/{1}".format(OUTDIR, t), 'wb') as f: pickle.dump(numexits, f)

    return "{0} {3}/{1} accept {2} {5}/{1} accept {4}".format(t, totalallowed, maxport, numexits[maxport], minport, numexits[minport])

def load_data(nsf):
    with open(nsf, 'rb') as ns: return pickle.load(ns), pickle.load(ns)

def get_network_state_files(network_state_dir):
    nsfs = []
    for dirpath, dirnames, filenames in os.walk(network_state_dir, followlinks=True):
        for filename in filenames:
            if (filename[0] != '.'):
                nsfs.append(os.path.join(dirpath,filename))
    nsfs.sort(key = lambda x: os.path.basename(x))
    return nsfs

if __name__ == '__main__':
    main()
