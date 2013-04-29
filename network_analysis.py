import os.path
#import numpypy
import numpy
import cPickle as pickle
from pathsim import *
import multiprocessing
import math

def linear_regression(x, y):
    """Does single linear regression on input data.
    Returns coefficients for line ax+b and r^2 coefficient."""
    A = numpy.vstack([x, numpy.ones(len(x))]).T
    coefs, residuals, rank, s = numpy.linalg.lstsq(A, y)
    a, b = coefs
    y_avg = float(sum(y)) / len(y)
    ss = 0
    for i in xrange(len(y)):
        ss += (y[i] - y_avg)**2
    r_squared = 1 - residuals[0]/float(ss)
    return (a, b, r_squared)


def get_network_stats_from_output(filename):
    """Read in stats from output of
    pathsim_analysis.network_analysis_print_guards_and_exits()."""
    initial_guards = {}
    exits_tot_bw = {}
    
    in_reading = False
    with open(filename) as f:
        # read past initial lines showing network states files read
        while True:
            line = f.readline()
            if (line[0:5] == 'Using') or (line[0:7] == 'Filling'):
                in_reading = True
            if in_reading and (line[0:5] != 'Using') and (line[0:7] != 'Filling'):
                print('Left reading: {0}'.format(line))
                break
        # get past headers
        line = f.readline()
        line = f.readline()
        line = f.readline()
        while (line[0:3] != 'Top'):
            line_split = line.split()
            id = int(line_split[0])
            if line_split[1]:
                prob = float(line_split[1])
            else:
                print('ERR: {0}'.format(id))
            uptime = int(line_split[2])
            if line_split[3]:
                cons_bw = float(line_split[3])
            else:
                print('ERR: {0}'.format(id))
            if line_split[4]:
                avg_average_bw = float(line_split[4])
            else:
                print('ERR: {0}'.format(id))
            if line_split[5]:
                avg_observed_bw = float(line_split[5])
            else:
                print('ERR: {0}'.format(id))
            fingerprint = line_split[6]
            nickname = line_split[7] 
            initial_guards[fingerprint] = {\
                'nickname':nickname,
                'prob':prob,
                'uptime':uptime,
                'cons_bw':cons_bw,
                'avg_average_bandwidth':avg_average_bw,
                'avg_observed_bandwidth':avg_observed_bw}
            line = f.readline()
        print('Reading exits')
        # get past next header
        line = f.readline()
        for line in f:
            line_split = line.split()
            id = int(line_split[0])
            if line_split[1]:
                tot_prob = float(line_split[1])
            else:
                print('ERR tot_prob: {0}'.format(id))            
            if line_split[2]:
                max_prob = float(line_split[2])
            else:
                print('ERR max_prob: {0}'.format(id))        
            if line_split[3]: 
                min_prob = float(line_split[3])
            else:
                print('ERR min_prob: {0}'.format(id))
            if line_split[4]:        
                avg_cons_bw = float(line_split[4])
            else:
                print('ERR avg_cons_bw: {0}'.format(id))
            if line_split[5]:        
                avg_average_bw = float(line_split[5])
            else:
                print('ERR avg_average_bw: {0}'.format(id))
            if line_split[6]:
                avg_observed_bw = float(line_split[6])
            else:
                print('ERR avg_observed_bw: {0}'.format(id))        
            uptime = int(line_split[7])
            fingerprint = line_split[8]
            nickname = line_split[9]
            exits_tot_bw[fingerprint] = {\
                'tot_prob':tot_prob,
                'nickname':nickname,
                'max_prob':max_prob,
                'min_prob':min_prob,
                'tot_cons_bw':avg_cons_bw,
                'tot_average_bandwidth':avg_average_bw,
                'tot_observed_bandwidth':avg_observed_bw,
                'uptime':uptime}
    return (initial_guards, exits_tot_bw)

def find_needed_guard_bws():
    """Find consensus values and matching bandwidth that would give you some
    fraction of guard selection prob."""
    filename = 'out/analyze/network/analyze.network.2013-01--03.out'
    out_dir = 'out/analyze/network/'       
#    (initial_guards, exits_tot_bw) = get_network_stats_from_output(filename)
#    plot_against_consensus_bw(initial_guards, out_dir)

    initial_guards_file = \
        'out/analyze/network/initial_guards.2013-01--03.pickle'
    f = open(initial_guards_file)
    initial_guards = pickle.load(f)
    f.close()

    ns_file = 'out/network-state/slim-filtered/network-state-2013-01/2013-01-01-00-00-00-network_state'
    f = open(ns_file)
    consensus = pickle.load(f)
    f.close()

    guard_cons_bw = []
    guard_prob = []
    guard_avg_avg_bw = []
    guard_avg_obs_bw = []
    for fprint, guard in initial_guards.items():
        guard_cons_bw.append(guard['rel_stat'].bandwidth)
        guard_prob.append(guard['prob'])
        guard_avg_avg_bw.append(float(guard['tot_average_bandwidth'])/\
            float(guard['uptime']))
        guard_avg_obs_bw.append(float(guard['tot_observed_bandwidth'])/\
            float(guard['uptime']))
    
    desired_prob = .1
    needed_weighted_cons_bw = 0
    guard_weights = get_position_weights(initial_guards.keys(),
                    consensus.relays, 'g', consensus.bandwidth_weights, 
                    consensus.bwweightscale)
    tot_cons_bw = 0
    for fprint, guard in initial_guards.items():
        tot_cons_bw += guard_weights[fprint]
    needed_weighted_cons_bw = desired_prob * float(tot_cons_bw) / (1-desired_prob)
    adv_guard_flags = [stem.Flag.FAST, stem.Flag.GUARD, stem.Flag.RUNNING, \
                stem.Flag.STABLE, stem.Flag.VALID]
    adv_bw_weight = get_bw_weight(adv_guard_flags, 'g',
        consensus.bandwidth_weights)    
    needed_cons_bw = needed_weighted_cons_bw *\
        float(consensus.bwweightscale)/adv_bw_weight
        
    # linear regression on this data
    (a, b, r_squared) = linear_regression(guard_cons_bw, guard_avg_obs_bw)
    needed_bw = a*needed_cons_bw + b       

    return (needed_cons_bw, needed_bw, a, b, r_squared)


def get_exit_bws_helper(ns_file):
    """Returns lists of exits bandwidths."""
    need_fast = True
    need_stable = False
    need_internal = False    
    
    
    cons_rel_stats = {}    
    with open(ns_file, 'r') as nsf:
        consensus = pickle.load(nsf)
        descriptors = pickle.load(nsf)
        
    for relay in consensus.routers:
        if (relay in descriptors):
            cons_rel_stats[relay] = consensus.routers[relay]
                
    exits_cons_bws = []
    exits_obs_bws = []
    # get exit relays - with no ip:port in mind, we just look for
    # not policy_is_reject_star(exit_policy) 
    # with sum of weighted selection probabilities
    exits = filter_exits(cons_rel_stats, descriptors, need_fast,\
        need_stable, need_internal, None, None)    
    for fprint in exits:
        exits_cons_bws.append(cons_rel_stats[fprint].bandwidth)
        exits_obs_bws.append(descriptors[fprint].observed_bandwidth)
    return (exits_cons_bws, exits_obs_bws)
    

def get_exit_bws(in_dir, num_processes):
    """Returns array of consensus bandwidths and observed bandwidths
    for exits.
    Inputs:
        in_dir: directory containing network state files to examine
        num_processes: number of processes to simultaneously process files"""
        
    network_state_files = []
    for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
        for filename in filenames:
            if (filename[0] != '.'):
                network_state_files.append(os.path.join(dirpath,filename))
    
    network_state_files.sort(key = lambda x: os.path.basename(x))
    exits_cons_bws = []
    exits_obs_bws = []    
    
    chunksize = int(math.floor(float(len(network_state_files)) /\
        num_processes))
    pool = multiprocessing.Pool(num_processes)
    process_bws = pool.map(get_exit_bws_helper, network_state_files, chunksize)
    pool.close()
    print('Number of individual bw lists: {0}'.format(len(process_bws)))
    print('Max cons bw list length: {0}'.format(max(map(lambda x: len(x[0]),
        process_bws))))
    print('Max obs bw list length: {0}'.format(max(map(lambda x: len(x[1]),
        process_bws))))
    print('Min cons bw list length: {0}'.format(min(map(lambda x: len(x[0]),
        process_bws))))
    print('Min obs bw list length: {0}'.format(min(map(lambda x: len(x[1]),
        process_bws))))

    for process_cons_bws, process_obs_bws in process_bws:
        exits_cons_bws.extend(process_cons_bws)
        exits_obs_bws.extend(process_obs_bws)
    print('len(exits_cons_bws): {0}'.format(len(exits_cons_bws)))
    print('len(exits_obs_bws): {0}'.format(len(exits_obs_bws)))    
    print('First elements: {0}; {1}'.format(exits_cons_bws[0],
        exits_obs_bws[0]))
    return (exits_cons_bws, exits_obs_bws)
    
def get_exit_regression(in_dir, num_processes):
    """Uses exit relay to calculate regression coefficients for
    consensus bandwidth to observed bandwidth.
    Separated from get_exit_bws somewhat artificially because
    numpy.vstack in linear_regression doesn't work in pypy's numpypy."""


    (exits_cons_bws, exits_obs_bws) =  get_exit_bws(in_dir, num_processes)
    (a, b, r_squared) = linear_regression(exits_cons_bws,
        exits_obs_bws)
        
    return (a, b, r_squared)


if __name__ == '__main__':
    (needed_cons_bw, needed_bw, guard_a, guard_b, guard_r_squared) =\
        find_needed_guard_bws()
### Output:
### a = 299.45192815560563
### b = 1104612.6683457776
### r_squared = 0.74124917207592156
### needed_cons_bw = 365924.087681159
### needed_bw = 110681286.28304975
    
    in_dir = 'out/network-state/fat/ns-2013-01--03'    
    (exit_a, exit_b, exit_r_squared) = get_exit_regression(in_dir, 20)
    print('a = {0}'.format(exit_a))
    print('b = {0}'.format(exit_b))
    print('r^2 = {0}'.format(exit_r_squared))
### Output:
### a = 215.85762129136413
### b = 1010231.1684564484
### r_squared = 0.68600871839386535
