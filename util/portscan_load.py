#!/usr/bin/python

import os, sys
import cPickle as pickle

def main():
    scans = get_portscans("portscan_all_output/")
    for scan in scans:
        numexits = None
        with open(scan, 'rb') as f: numexits = pickle.load(f)
        maxport = max(numexits, key=lambda x:numexits[x])
        minport = min(numexits, key=lambda x:numexits[x])
        print "{0} {3}/{1} accept {2} {5}/{1} accept {4}".format(os.path.basename(scan), 0, maxport, numexits[maxport], minport, numexits[minport])
        
def get_portscans(portscan_dir):
    scans = []
    for dirpath, dirnames, filenames in os.walk(portscan_dir, followlinks=True):
        for filename in filenames:
            if (filename[0] != '.'):
                scans.append(os.path.join(dirpath,filename))
    scans.sort(key = lambda x: os.path.basename(x))
    return scans

if __name__ == '__main__':
    main()
