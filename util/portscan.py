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

if len(sys.argv) != 2: print "USAGE: {0} network_state_file".format(sys.argv[0]);sys.exit()
if not os.path.exists(OUTDIR): os.mkdir(OUTDIR)

allports = [i+1 for i in xrange(65535)]
longlivedports = [21, 22, 706, 1863, 5050, 5190, 5222, 5223, 6523, 6667, 6697, 8300]
defaultexitpolicy = stem.exit_policy.ExitPolicy("reject *:25", "reject *:119", "reject *:135-139", "reject *:445", "reject *:563", "reject *:1214", "reject *:4661-4666", "reject *:6346-6429", "reject *:6699", "reject *:6881-6999", "accept *:*")

# check this subset
ports = allports if SCANALLPORTS else [21, 22, 25, 80, 443, 6699, 8080, 9000, 9001]

def main():
    nsf = sys.argv[1]
    result = process_nsf(nsf, dump=True)
    if result is not None: print result

def process_nsf(nsf, dump=False):
    numexits = {} # port:counter for number of relays that exit to port
    totalallowed, totalbw, donecounting = 0, 0, False
    base = os.path.basename(nsf)
    consensus, descriptors = load_data(nsf)

    t = consensus.valid_after.isoformat()
    if SCANALLPORTS and "T00:00:00" not in t: return None

    for p in ports:
        if not defaultexitpolicy.can_exit_to(port=p, strict=True): continue
        numexits[p] = [0,0]
        needstable = p in longlivedports
        for relay in consensus.relays:
            if relay in descriptors: 
                rse = consensus.relays[relay] # router status entry
                sd = descriptors[relay] # server descriptor
                if sd.exit_policy.is_exiting_allowed(): 
                    exitweight = get_bw_weight(rse.flags, 'e', consensus.bandwidth_weights)
                    bw = rse.bandwidth * exitweight
                    if not donecounting:
                        totalallowed += 1
                        totalbw += bw
                    canexit = sd.exit_policy.can_exit_to(port=p, strict=True)
                    if canexit and (not needstable or (needstable and "Stable" in rse.flags)): 
                        numexits[p][0] += 1
                        numexits[p][1] += bw
        donecounting = True
    maxport = max(numexits, key=lambda x:numexits[x][1]) # port with highest bw weight
    minport = min(numexits, key=lambda x:numexits[x][1]) # port with lowest bw weight

    if dump:
        with open("{0}/{1}".format(OUTDIR, t), 'wb') as f: pickle.dump(numexits, f)

    return "{0} {3}/{1} accept {2} with weight {6}/{8} {5}/{1} accept {4} with weight {7}/{8}".format(t, totalallowed, maxport, numexits[maxport][0], minport, numexits[minport][0], numexits[maxport][1], numexits[minport][1], totalbw)

def load_data(nsf):
    with open(nsf, 'rb') as ns: return pickle.load(ns), pickle.load(ns)

if __name__ == '__main__':
    main()
