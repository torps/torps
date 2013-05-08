
##### Examine user traces an models #####
# "facebook"
# "gmailgchat"
# "gcalgdocs"
# "websearch"
# "irc"
# "bittorrent"
# 'typical'
import models
import cPickle as pickle

tracefile = 'in/users2-processed.traces.pickle'
tracename = 'typical'

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
       
# streams to 9001
or_port_streams = []
for stream in streams:
    if (9001 == stream[2]):
        or_port_streams.append(stream)
        
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
# start_time: 1330646400
# end_time: 1335830399

# facebook trace
# num streams in trace: 43
# ips
  # num: 36
# ports
  # num: 2
  # [80, 443]
  
# gmailgchat trace
# num streams in trace: 40
# ips
    # num: 39
# ports
  # num: 2
  # [80, 443]
  
# gcalgdocs trace
# num streams in trace: 17
# ips
    # num: 16
# ports
  # num: 2
  # [80, 443]  
  
# websearch trace
# num streams in trace: 138
# ips
    # num: 123
# ports
  # num: 2
  # [80, 443] 
  
#irc trace
# num streams in trace: 1
# ips
    # num: 1
# ports
  # num: 1
  # [6697]  
     
# bittorrent trace
# num streams in trace: 188
# ips
    # num: 171
# ports
  # num: 118  
  
# Model streams / week
# simple: 1008
# irc: 1 * 27 * 5 = 135
# bittorrent: 2*18*188 = 6768 streams / week
# typical 7*(1 facebook, 1 gcalgdocs, 1 gmailgchat, 2 websearch)
#   7*(43 + 17 + 40 + 2*138) = 2632 streams/week
# Model IPs:
#  typical: 205
#  irc: 1
#  bittorrent: 171
# Model Ports:
#  typical: 2
#  irc: 1
#  bittorrent: 118

###### 

##### Finding and plotting the probabilities of compromise for the
# bandwidth-allocation experiments.
import pathsim_analysis
import os

# guard bw : exit bw
#1:1                                                      
#5:1                                    
#10:1                                    
#50:1                                   
guard_bws = [52428800, 69905067, 87381333, 95325091, 102801568]
exit_bws = [52428800, 34952533, 17476267, 9532509, 2056031]

# using regression from 3-month consensuses (1/13-3/13)
# guard_cons_bws = [171394, 229755, 288115, 314643, 339610]
# exit_cons_bws = [238205, 157244, 76282, 39481, 4845]
# date_range = '2013-01--03'

# using regression from 6-month consensuses (10/12-3/13)
guard_cons_bws = [266016, 357064, 448112, 489497, 528558]
exit_cons_bws = [256368, 169200, 82033, 42411, 5120]
date_range = '2012-10--2013-03'

guard_compromise_probs = []
exit_compromise_probs = []
guard_exit_compromise_probs = []
for guard_cons_bw, exit_cons_bw in zip(guard_cons_bws, exit_cons_bws):
    in_dir = 'out/analyze/typical.' + date_range + '.' + str(guard_cons_bw) +\
        '-' + str(exit_cons_bw) + '-0-adv/data/'
    print('Calculating compromise probs for {0}'.format(in_dir))
    pathnames = []
    for dirpath, dirnames, fnames in os.walk(in_dir):
        for fname in fnames:
            pathnames.append(os.path.join(dirpath,fname))
    pathnames.sort()
    (guard_comp_prob, exit_comp_prob, guard_exit_comp_prob) =\
        pathsim_analysis.compromised_set_get_compromise_probs(pathnames)
    guard_compromise_probs.append(guard_comp_prob)
    exit_compromise_probs.append(exit_comp_prob)
    guard_exit_compromise_probs.append(guard_exit_comp_prob)
    
# Output for 1/13 - 3/13
#>>> guard_compromise_probs
#[0.3759, 0.46332, 0.54293, 0.57084, 0.59832]
#>>> exit_compromise_probs
#[1.0, 1.0, 1.0, 1.0, 0.78898]
#>>> guard_exit_compromise_probs
#[0.37018, 0.45306, 0.51329, 0.48526, 0.14866]

# Output for 10/12 - 3/13
#>>> guard_compromise_probs
#[0.72073, 0.81337, 0.8724, 0.89328, 0.91033]
#>>> exit_compromise_probs
#[1.0, 1.0, 1.0, 1.0, 0.967]
#>>> guard_exit_compromise_probs
#[0.71705, 0.8086, 0.85816, 0.84255, 0.36203]


guard_compromise_rates = []
exit_compromise_rates = []
guard_exit_compromise_rates = []
for guard_cons_bw, exit_cons_bw in zip(guard_cons_bws, exit_cons_bws):
    in_dir = 'out/analyze/typical.' + date_range + '.' + str(guard_cons_bw) +\
        '-' + str(exit_cons_bw) + '-0-adv/data/'
    print('Calculating compromise rates for {0}'.format(in_dir))
    pathnames = []
    for dirpath, dirnames, fnames in os.walk(in_dir):
        for fname in fnames:
            pathnames.append(os.path.join(dirpath,fname))
    pathnames.sort()
    (guard_comp_rate, exit_comp_rate, guard_exit_comp_rate) =\
        pathsim_analysis.compromised_set_get_compromise_rates(pathnames)
    guard_compromise_rates.append(guard_comp_rate)
    exit_compromise_rates.append(exit_comp_rate)
    guard_exit_compromise_rates.append(guard_exit_comp_rate)

# Output for 10/12 - 3/13
#>>> guard_compromise_rates
#[0.08862985766892682, 0.11062274842179097, 0.12933955561725508, 0.1376146406651859, 0.1444471478255787]
#>>> exit_compromise_rates
#[0.06573084390343699, 0.044700403904606036, 0.022366468757306524, 0.011749066080196399, 0.0014427535363572598]
#>>> guard_exit_compromise_rates
#[0.005790726999064765, 0.004911905395136778, 0.00288130231470657, 0.0016003154956745382, 0.00020887114215571663]



# Plot output
import numpy
import matplotlib
matplotlib.use('PDF')
import matplotlib.pyplot
fig = matplotlib.pyplot.figure(figsize = (8, 4))

# fraction of bandwidth allocated to guard
x = [1.0/2.0, 2.0/3.0, 5.0/6.0, 10.0/11.0, 50.0/51.0]
matplotlib.pyplot.plot(x, guard_exit_compromise_probs, '-v',
    label = 'Prob. of guard & exit compromise', linewidth = 2,
    markersize = 8)
matplotlib.pyplot.plot(x, guard_compromise_probs, '-o',
    label = 'Prob. of guard compromise', linewidth = 2,
    markersize = 8)
matplotlib.pyplot.plot(x, exit_compromise_probs, '-s',
    label = 'Prob. of exit compromise', linewidth = 2,
    markersize = 8)
#guard_compromise_rates = []
#exit_compromise_rates = []
#guard_exit_compromise_rates = []
matplotlib.pyplot.plot(x, guard_compromise_rates, '-*',
    label = 'Avg. guard compromise rate', linewidth = 2,
    markersize = 8)
matplotlib.pyplot.plot(x, exit_compromise_rates, '-x',
    label = 'Avg. exit compromise rate', linewidth = 2,
    markersize = 8)
matplotlib.pyplot.legend(loc='center left', fontsize = 'x-large')
matplotlib.pyplot.ylim(ymin=0.0)
matplotlib.pyplot.yticks(numpy.arange(0, 1.1, 0.1))
matplotlib.pyplot.xlabel('Fraction of 100MiBps total bandwidth allocated to guard', fontsize = 'x-large')
matplotlib.pyplot.ylabel('Probability', fontsize = 'x-large')
#matplotlib.pyplot.title('Compromise probability and rates, 10/12 - 3/13')

# output
matplotlib.pyplot.savefig('out/analyze/vary_allocation.2012-10--2013-03/vary_allocation.2012-10--2013-03.compromise_probs_rates.pdf')

##### Working out parallelization of network analysis #####
import os
import math
import multiprocessing
import cPickle as pickle
def get_num_relays(ns_file):
    with open(ns_file, 'r') as nsf:
        consensus = pickle.load(nsf)
        descriptors = pickle.load(nsf)
    num_relays = 0    
    for relay in consensus.routers:
        if (relay in descriptors):
            num_relays += 1
    return num_relays


base_dir = '/mnt/ram/'
in_dir = base_dir + 'out/network-state/fat/network-state-2013-01'

network_state_files = []
for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
    for filename in filenames:
        if (filename[0] != '.'):
            network_state_files.append(os.path.join(dirpath,filename))

num_processors = 20
chunksize = int(math.floor(float(len(network_state_files)) / num_processors))
pool = multiprocessing.Pool(num_processors)
nums = pool.map(get_num_relays, network_state_files, chunksize)
pool.close()
print('max relays: {0}'.format(max(nums)))
print('min relays: {1}'.format(min(nums)))
print('tot num relays: {2}'.format(sum(nums)))
##########

##### Create graphs with lines from multiple experiments #####
# varying user models
out_dir = 'out/analyze/user-models.2012-10--2013-03.448112-82033-0-adv'
out_name = 'user-models.2012-10--2013-03.448112-82033-0-adv'
in_dirs = ['out/analyze/typical.2012-10--2013-03.448112-82033-0-adv/data',
    'out/analyze/bittorrent.2012-10--2013-03.448112-82033-0-adv/data',
    'out/analyze/irc.2012-10--2013-03.448112-82033-0-adv/data',
    'out/analyze/worst.2012-10--2013-03.448112-82033-0-adv/data',
    'out/analyze/best.2012-10--2013-03.448112-82033-0-adv/data']
line_labels = ['typical', 'bittorrent', 'irc', 'worst', 'best']
pathnames_list = []
for in_dir in in_dirs:
    pathnames = []
    for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
        for filename in filenames:
            if (filename[0] != '.'):
                pathnames.append(os.path.join(dirpath,filename))
    pathnames_list.append(pathnames)
pathsim_plot.compromised_set_plot(pathnames_list, line_labels, out_dir, out_name, figsize = (8, 4.5), fontsize = 'xx-large')

# varying total bandwidth and entry time
# using regression from 3-month consensuses (1/13-3/13)
# 	200: 174762666.0 / 34952533; 579920 / 157244
#	100: 87381333 / 17476266; 288115 / 76282
#	50: 43690666 / 8738133; 142213 / 35801
#	25: 21845333 / 4369066; 69262 / 15560
#	10: 8738133 / 1747626; 25492 / 3416
# using regression from 6-month consensuses (10/12-3/13)
# 	200: 174762666.0 / 34952533; 903352 / 169200
#	100: 87381333 / 17476266; 448112 / 82033
#	50: 43690666 / 8738133; 220492 / 38449
#	25: 21845333 / 4369066; 106682 / 16657
#	10: 8738133 / 1747626; 38396 / 3582
out_dir = 'out/analyze/vary-bandwidth.2012-10--2013-03'
out_name = 'vary-bandwidth.2012-10--2013-03'
in_dirs = ['out/analyze/typical.2012-10--2013-03.903352-169200-0-adv/data',
    'out/analyze/typical.2012-10--2013-03.448112-82033-0-adv/data',
    'out/analyze/typical.2012-10--2013-03.220492-38449-0-adv/data',
    'out/analyze/typical.2012-10--2013-03.106682-16657-0-adv/data',
    'out/analyze/typical.2012-10--2013-03.38396-3582-0-adv/data',
    'out/analyze/typical.2012-10--2013-03.448112-82033-1354320000-adv/data']
line_labels = ['200 MiB/s', '100 MiB/s', '50 MiB/s', '25 MiB/s', '10 MiB/s', 'relay entry day 62']
pathnames_list = []
for in_dir in in_dirs:
    pathnames = []
    for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
        for filename in filenames:
            if (filename[0] != '.'):
                pathnames.append(os.path.join(dirpath,filename))
    pathnames_list.append(pathnames)
pathsim_plot.compromised_set_plot(pathnames_list, line_labels, out_dir, out_name, fontsize = 'large')

##########

##### Getting all destination IPs from any trace #####
from models import *
tracefilename = 'in/users2-processed.traces.pickle'
ut = UserTraces.from_pickle(tracefilename)

trace_dest_ips = {}
for tracename in ["facebook", "gmailgchat", "gcalgdocs", "websearch", "irc",
    "bittorrent"]:
    trace_dest_ips[tracename] = set()    
    for seconds, ip, port in ut.trace[tracename]:
        trace_dest_ips[tracename].add(ip)
trace_dest_ips['typical'] = set()
for tracename in ["facebook", "gmailgchat", "gcalgdocs", "websearch"]:
    trace_dest_ips['typical'].update(trace_dest_ips[tracename])

for tracename in ['typical', 'irc', 'bittorrent']:
    out_file = '{0}_dest_ips.txt'.format(tracename)
    with open(out_file, 'w') as f:
        for ip in trace_dest_ips[tracename]:
            f.write('{0}\n'.format(ip))

##### Finding families and total bandwidths #####
import network_analysis
network_state_file = 'out/network-state/fat/network-state-2013-03/2013-03-31-23-00-00-network_state'
families_bw = network_analysis.get_families(network_state_file)
# look at largest by min(obs_bw, avg_bw)
families_bw.sort(key = lambda x: min(x[1], x[2]), reverse=True)
#(tot_cons_bw, tot_obs_bw, tot_avg_bw, family)
with open(network_state_file) as nsf:
    consensus = pickle.load(nsf)
    descriptors = pickle.load(nsf)
print('Tot cons bw\tTot bw est.\tTot obs bw (MiBps)\tTot avg bw (MiBps)\tLargest member')
for i in xrange(10):
    cons_bw = families_bw[i][0]
    # use 10/12-3/13 exit regression coefficients to estimate bw in another way
    exit_a = 200.49050736264786
    exit_b = 1029509.7491675143
    est_cons_bw = float(exit_a * cons_bw + exit_b) / (1024*1024)
    obs_bw = float(families_bw[i][1])/(1024*1024)
    avg_bw = float(families_bw[i][2])/(1024*1024)
    # use relay with largest consensus bw as representative
    rep = None
    rep_cons_bw = 0
    for fprint in families_bw[i][3][0]:
        if (rep == None) or\
            (consensus.routers[fprint].bandwidth >= rep_cons_bw):
            rep = consensus.routers[fprint].nickname
            rep_cons_bw = consensus.routers[fprint].bandwidth
    print('{0}\t{1}\t{2}\t{3}\t{4}'.format(cons_bw, est_cons_bw, obs_bw,
        avg_bw, rep))

# Output
# 500008	96.584670405	260.515003204	683.53515625	herngaard
# 601100	115.913728452	115.710887909	5120.0	chaoscomputerclub19
# 245291	47.8821056277	107.816354752	132.421875	ndnr1
# 231900	45.3217109743	95.2884531021	6144.0	GoldDragon
# 171346	33.7436258542	86.9247703552	80.5224609375	Paint

##########

##### Examine exit distributions  for the ip/port pairs in traces #####
# "irc"
# "bittorrent"
# 'typical'
import os.path
from pathsim import *
import cPickle as pickle
import models

nsf_dir = 'out/network-state/slim/network-state-2013-03'
network_state_file = '2013-03-31-23-00-00-network_state'
nsf_pathname = os.path.join(nsf_dir, network_state_file)
with open(nsf_pathname, 'rb') as nsf:
    consensus = pickle.load(nsf)
    descriptors = pickle.load(nsf)
cons_rel_stats = {}
for fprint in consensus.relays:
    if (fprint in descriptors):
        cons_rel_stats[fprint] = consensus.relays[fprint]

tracefile = 'in/users2-processed.traces.pickle'
with open(tracefile) as f:
    obj = pickle.load(f)
streams = dict()
streams['bittorrent'] = obj.trace['bittorrent']
streams['typical'] = []
for tracename in ["facebook", "gmailgchat", "gcalgdocs", "websearch"]:
    streams['typical'].extend(obj.trace[tracename])
streams['irc'] = obj.trace['irc']

# ips and ports
dests = dict()
for model in ['bittorrent', 'typical', 'irc']:
    dests[model] = set()
    for stream in streams[model]:
        dests[model].add((stream[1], stream[2]))
ips = dict()
for model in ['bittorrent', 'typical', 'irc']:
    ips[model] = set()
    for stream in streams[model]:
        ips[model].add(stream[1])
ports = dict()
for model in ['bittorrent', 'typical', 'irc']:
    ports[model] = set()
    for stream in streams[model]:
        ports[model].add(stream[2])

# find total consensus bw for a given ip:port
def get_exit_bw_for_dest(ip, port, cons_rel_stats, descriptors, bw_weights,
    bwweightscale):
    fast = True
    stable = (port in TorOptions.long_lived_ports)
    internal = False
    exits = filter_exits(cons_rel_stats, descriptors, fast, stable, internal,
        ip, port)
    weights = get_position_weights(exits, cons_rel_stats, 'e',
        bw_weights, bwweightscale)
    tot_cons_bw = 0
    for exit in exits:
        tot_cons_bw += weights[exit]
    return tot_cons_bw

# find total consensus bw for each ip:port in given consensus
dests_weights = dict()
for model in ['bittorrent', 'typical', 'irc']:
    dests_weights[model] = []
    for ip, port in dests[model]:
        tot_cons_bw = get_exit_bw_for_dest(ip, port, cons_rel_stats,
            descriptors, consensus.bandwidth_weights, consensus.bwweightscale)
        dests_weights[model].append((ip, port, tot_cons_bw))
    dests_weights[model].sort(key = lambda x: x[2])
# print list
model = 'bittorrent'
for ip, port, wt in dests_weights[model]:
    print('{0}\t{1}\t{2}'.format(ip, port, wt))    
##########

##### Calculating network statistics #####
import pathsim
import os
import cPickle as pickle
import numpypy # to allow pypy to be used
import network_analysis
import stem
in_dir = '/mnt/ram/out/network-state/fat/ns-2012-10--2013-03'
num_processes = 40
# total guard cons bw
# total (non-port) exit bw (maybe 80)
# total worst-port / best-port exit bw (6523 / 443, maybe 80)
# total bw for ip/port pairs in streams
# guard churn, hibernation
def get_network_stats(network_state_file):
    """Returns stats on guard bw and exit bw."""
    if (network_state_file == None):
        return None
    with open(network_state_file, 'rb') as nsf:
        consensus = pickle.load(nsf)
        descriptors = pickle.load(nsf)
        hibernating_statuses = pickle.load(nsf)    
    cons_rel_stats = {}
    # remove relays without a descriptor
    for fprint in consensus.routers:
        if (fprint in descriptors):
            cons_rel_stats[fprint] = consensus.routers[fprint]
    # remove hibernating relays (ignore hibernating during period)
    hibernating_status = {}
    while (hibernating_statuses) and\
        (hibernating_statuses[-1][0] <= 0):
        hs = hibernating_statuses.pop()
        hibernating_status[hs[1]] = hs[2]
    # get non-hibernating guards
    guards = pathsim.filter_guards(cons_rel_stats, descriptors)
    # further use circuit-level filters that apply to all circuits
    stable = False
    guards = filter(lambda x: (stem.Flag.FAST in cons_rel_stats[x].flags) and\
        ((not stable) or (stem.Flag.STABLE in rel_stat.flags)) and\
        (hibernating_status[x] == False),
        guards)
    # calculate total guard consensus weight, obs bw, and adv bw
    tot_guard_cons_bw = 0
    tot_guard_avg_bw = 0
    tot_guard_obs_bw = 0
    for guard in guards:
        tot_guard_cons_bw += cons_rel_stats[guard].bandwidth
        tot_guard_avg_bw += descriptors[guard].average_bandwidth
        tot_guard_obs_bw += descriptors[guard].observed_bandwidth
    return (network_state_file, tot_guard_cons_bw, tot_guard_avg_bw, tot_guard_obs_bw)

network_stats = network_analysis.map_files(in_dir, get_network_stats,
    num_processes)
##########

##### Splitting guard bandwidth among multiple relays #####
#	100: 87381333 / 17476266; 448112 / 82033
# regression parameters from 10/12 - 3/13
# guard_a = 191.94548955003913
# guard_b = 1368281.674385923
num_adv_guards = 3
#>>> (87381333 / float(num_adv_guards) - guard_b) / guard_a
#144618.29444748428
##########