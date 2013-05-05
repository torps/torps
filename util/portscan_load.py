#!/usr/bin/python

import os, sys
import cPickle as pickle

longlivedports = [21, 22, 706, 1863, 5050, 5190, 5222, 5223, 6523, 6667, 6697, 8300]

def main():
    exitbw = {} # exitbw[port] = list of exit bw weights
    scans = get_portscans("portscan_all_output-exitweights/")
    numscans = len(scans)
    totalbw = 0.0
    for scan in scans:
        numexits = None
        with open(scan, 'rb') as f: numexits = pickle.load(f)
        for port in numexits:
            if port not in exitbw: exitbw[port] = []
            w = numexits[port][1]
            exitbw[port].append(w)
            totalbw += w
        '''
        maxport = max(numexits, key=lambda x:numexits[x][1]) # port with max bw weight ([x][0] is num exits)
        minport = min(numexits, key=lambda x:numexits[x][1]) # port with min bw weight
        if minport == 8300:
            numexits.pop(minport, None)
            minport = min(numexits, key=lambda x:numexits[x][1]) # port with min bw weight 
        print "{0} port {1} accepted by {2} with bw {3} port {4} accepted by {5} with bw {6}".format(os.path.basename(scan), maxport, numexits[maxport][0], numexits[maxport][1], minport, numexits[minport][0], numexits[minport][1])
        '''

    sortedexitbw = sorted(exitbw, key=lambda x:sum(exitbw[x]))
    l = len(sortedexitbw)
    print "exit bw weight by port:\nrank port mean_weight"
    for i in xrange(10):
        port = sortedexitbw[i]
        print i, port, sum(exitbw[port])/l
    for i in xrange(l-10, l):
        port = sortedexitbw[i]
        print i, port, sum(exitbw[port])/l
        
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
