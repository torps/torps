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
    network_analysis_print_guards_and_exits()."""
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
    
    
def get_guards_and_exits(network_state_files):
    """Takes list of network state files (expects fat ones), pads the sorted
    list for missing periods, and returns selection statistics about initial
    guards and exits."""
    network_state_files.sort(key = lambda x: os.path.basename(x))
    network_state_files = pad_network_state_files(network_state_files)
    
    initial_guards = {}
    exits_tot_bw = {} # rel_stat -> sum of hours active weighted by exit prob.
    
    need_fast = True
    need_stable = False
    need_internal = False

    consensus = None
    descriptors = None
    cons_valid_after = None
    cons_fresh_until = None
    cons_bw_weights = None
    cons_bwweightscale = None        
    init = True
    for ns_file in network_state_files:
        if (ns_file != None):
            print('Using file {0}'.format(ns_file))
        
            with open(ns_file, 'r') as nsf:
                consensus = pickle.load(nsf)
                descriptors = pickle.load(nsf)
                hibernating_statuses = pickle.load(nsf)
                cons_rel_stats = {}
                
                # set variables from consensus
                cons_valid_after = timestamp(consensus.valid_after)            
                cons_fresh_until = timestamp(consensus.fresh_until)
                cons_bw_weights = consensus.bandwidth_weights
                if ('bwweightscale' not in consensus.params):
                    cons_bwweightscale = TorOptions.default_bwweightscale
                else:
                    cons_bwweightscale = \
                        consensus.params['bwweightscale']
                
                for relay in consensus.routers:
                    if (relay in descriptors):
                        cons_rel_stats[relay] = consensus.routers[relay]
        else:
            if (cons_valid_after == None) or (cons_fresh_until == None):
                raise ValueError('Network status files begin with "None".')
            # gap in consensuses, just advance an hour, keeping network state  
            cons_valid_after += 3600
            cons_fresh_until += 3600
            print('Filling in gap from {0} to {1}'.format(cons_valid_after,\
                cons_fresh_until))
            # set empty statuses, even though previous should have been emptied
            hibernating_statuses = []
            
        # don't bother to maintain or use hibernating statuses
        
        # get initial entry guards w/ selection prob., uptime, and other stats
        if init:
            init = False
            guards = filter_guards(cons_rel_stats, descriptors)
            guard_weights = get_position_weights(guards,\
                cons_rel_stats, 'g', cons_bw_weights, cons_bwweightscale)
            cum_weighted_guards = get_weighted_nodes(guards,\
                guard_weights)
            # add in circuit requirements (what guard_filter_for_circ would do)
            # because we don't have a circuit it mind, this is just a FAST flag
            # also turn cumulative probs into individual ones
            cum_weight_old = 0
            for fprint, cum_weight in cum_weighted_guards:
                rel_stat = cons_rel_stats[fprint]
                if (stem.Flag.FAST in rel_stat.flags):
                   desc = descriptors[fprint]
                   initial_guards[fprint] = {\
                    'rel_stat':rel_stat,
                    'prob':cum_weight-cum_weight_old,
                    'uptime':1,
                    'tot_average_bandwidth':desc.average_bandwidth,
                    'tot_burst_bandwidth':desc.burst_bandwidth,
                    'tot_observed_bandwidth':desc.observed_bandwidth}
                cum_weight_old = cum_weight
        else:
            # apply criteria used in setting bad_since
            for guard in initial_guards:
                if (guard in cons_rel_stats) and\
                    (stem.Flag.RUNNING in cons_rel_stats[guard].flags) and\
                    (stem.Flag.GUARD in cons_rel_stats[guard].flags):
                    desc = descriptors[guard]
                    initial_guards[guard]['uptime'] += 1
                    initial_guards[guard]['tot_average_bandwidth'] +=\
                        desc.average_bandwidth
                    initial_guards[guard]['tot_burst_bandwidth'] +=\
                        desc.burst_bandwidth
                    initial_guards[guard]['tot_observed_bandwidth'] +=\
                        desc.observed_bandwidth
                    
        # get exit relays - with no ip:port in mind, we just look for
        # not policy_is_reject_star(exit_policy) 
        # with sum of weighted selection probabilities
        exits = filter_exits(cons_rel_stats, descriptors, need_fast,\
            need_stable, need_internal, None, None)
        exit_weights = get_position_weights(\
            exits, cons_rel_stats, 'e',\
            cons_bw_weights, cons_bwweightscale)
        weighted_exits = get_weighted_nodes(\
            exits, exit_weights)
        
        cum_weight_old = 0
        for fprint, cum_weight in weighted_exits:
            if fprint not in exits_tot_bw:
                exits_tot_bw[fprint] =\
                    {'tot_prob':0,\
                    'nickname':cons_rel_stats[fprint].nickname,\
                    'max_prob':0,\
                    'min_prob':1,\
                    'tot_cons_bw':0,\
                    'tot_average_bandwidth':0,\
                    'tot_burst_bandwidth':0,\
                    'tot_observed_bandwidth':0,\
                    'uptime':0}
            prob = cum_weight - cum_weight_old
            exits_tot_bw[fprint]['tot_prob'] += prob
            exits_tot_bw[fprint]['max_prob'] = \
                max(exits_tot_bw[fprint]['max_prob'], prob)
            exits_tot_bw[fprint]['min_prob'] = \
                min(exits_tot_bw[fprint]['min_prob'], prob)
            exits_tot_bw[fprint]['tot_cons_bw'] +=\
                cons_rel_stats[fprint].bandwidth
            exits_tot_bw[fprint]['tot_average_bandwidth'] +=\
                descriptors[fprint].average_bandwidth
            exits_tot_bw[fprint]['tot_burst_bandwidth'] +=\
                descriptors[fprint].burst_bandwidth
            exits_tot_bw[fprint]['tot_observed_bandwidth'] +=\
                descriptors[fprint].observed_bandwidth
            exits_tot_bw[fprint]['uptime'] += 1
            cum_weight_old = cum_weight
            
    return (initial_guards, exits_tot_bw)
    

def print_guards_and_exits(initial_guards, exits_tot_bw, guard_cum_prob,
    num_exits):
    """Prints top initial guards comprising guard_cum_prob selection prob.
    and top num_exits exits."""
    # print out top initial guards comprising some total selection prob.
    initial_guards_items = initial_guards.items()
    initial_guards_items.sort(key = lambda x: x[1]['prob'], reverse=True)
    cum_prob = 0
    i = 1    
    print('Top initial guards comprising {0} total selection probability'.\
        format(guard_cum_prob))
    print('#\tProb.\tUptime\tCons. BW\tAvg. Avg. BW\tAvg. Observed BW\tFingerprint\t\t\t\t\t\t\tNickname')
    for fp, guard in initial_guards_items:
        if (cum_prob >= guard_cum_prob):
            break
        avg_average_bw = float(guard['tot_average_bandwidth']) /\
            float(guard['uptime'])
        avg_observed_bw = float(guard['tot_observed_bandwidth']) /\
            float(guard['uptime'])
        print('{0}\t{1:.4f}\t{2}\t{3}\t{4:.4f}\t{5:.4f}\t{6}\t{7}'.format(i,\
            guard['prob'], guard['uptime'], guard['rel_stat'].bandwidth,\
            avg_average_bw, avg_observed_bw, fp, guard['rel_stat'].nickname))
        cum_prob += guard['prob']
        i += 1

    # print out top exits by total probability-weighted uptime
    exits_tot_bw_sorted = exits_tot_bw.items()
    exits_tot_bw_sorted.sort(key = lambda x: x[1]['tot_prob'], reverse=True)
    i = 1
    print('Top {0} exits by probability-weighted uptime'.\
        format(num_exits))
    print('#\tCum. prob.\tMax prob.\tMin prob.\tAvg. Cons. BW\tAvg. Avg. BW\tAvg. Observed BW\tUptime\tFingerprint\t\t\t\t\t\t\tNickname')
    for fprint, bw_dict in exits_tot_bw_sorted[0:num_exits]:
        avg_cons_bw = float(bw_dict['tot_cons_bw']) / float(bw_dict['uptime'])
        avg_average_bw = float(bw_dict['tot_average_bandwidth'])/\
            float(bw_dict['uptime'])
        avg_observed_bw = float(bw_dict['tot_observed_bandwidth'])/\
            float(bw_dict['uptime'])
        print(\
        '{0}\t{1:.4f}\t{2:.4f}\t{3:.4f}\t{4:.4f}\t{5:.4f}\t{6:.4f}\t{7}\t{8}\t{9}'.\
            format(i, bw_dict['tot_prob'], bw_dict['max_prob'],\
                bw_dict['min_prob'], avg_cons_bw, avg_average_bw,\
                avg_observed_bw, bw_dict['uptime'], fprint,\
                bw_dict['nickname']))
        i += 1
    
def get_normalized_family(family):
    """Turn fingerprint string as listed in descriptor into normalized
    form."""
    
    normalized_family = set()
    for element in family:
        if (len(element) == 41) and (element[0] = '$'):
            # assume is the hex fingerprint
            normalized_family.add(element[1:].upper())
        else:
            normalized_family.add(element)
    return normalized_family
        
def get_families(network_state_file):
    """Finds top num_families families in a consensus by total consensus
    bandwidth."""
    #map_files(in_dir, map_files_map_fn, num_processes)
    with open(network_state_file) as nsf:
        consensus = pickle.load(nsf)
        descriptors = pickle.load(nsf)  
    # only keep those relays that have descriptors
    cons_rel_stats = {}
    for fprint in consensus.routers:
        if (fprint in descriptors):
            cons_rel_stats[fprint] = consensus.routers[fprint]
    # create families, enforcing transitivity
    # each family is a set of fingerprints and a set of nicknames in the family
    # and a set of fingerprints and nicknames pointed to by the the family
    # attribute of *any* family member
    families = [] 
    for fprint in cons_rel_stats:
        nickname = cons_rel_stats[fprint].nickname
        cur_fprints = {fprint}
        cur_nicknames = {nickname}
        cur_ptrs = get_normalized_family(descriptors[fprint].family)
        new_families = []
        while families:
            family_fprints, family_nicknames, family_ptrs = families.pop()
            if ((not cur_fprints.isdisjoint(family_ptrs)) or\
                    (not cur_nicknames.isdisjoint(family_ptrs))) and\
                ((not cur_ptrs.isdisjoint(family_fprints)) or\
                    (not cur_ptrs.isdisjoint(family_nicknames))):
                cur_fprints.update(family_fprints)
                cur_nicknames.update(family_nicknames)
                cur_ptrs.update(family_ptrs)
            else:
                new_families.append((family_fprints, family_nicknames,
                    family_ptrs))
        new_families.append((cur_fprints, cur_nicknames, cur_ptrs))
        families = new_families
    # add total consensus bandwidth and total observed bandwidth
    families_bw = []
    for family in families:
        family_fprints = family[0]
        tot_cons_bw = 0
        tot_obs_bw = 0
        for fprint in family_fprints:
            tot_cons_bw += cons_rel_stats[fprint].bandwidth
            tot_obs_bw += descriptors[fprint].observed_bandwidth
        families_bw.append((tot_cons_bw, tot_obs_bw, family))
    families_bw.sort(key = lambda x: x[0], reverse = True)
    return families_bw
        
        
def get_groups(initial_guards, exits_tot_bw, guard_substr, exit_substr):
    """Searches for guards and exits with nicknames containing respective
        input strings."""
    # find matching guards
    guard_group = []
    for fprint, guard in initial_guards.items():
        if (guard_substr in guard['rel_stat'].nickname):
            guard_group.append(fprint)
    #find matching exits
    exit_group = []
    for fprint, exit in exits_tot_bw.items():
        if (exit_substr in exit['nickname']):
            exit_group.append(fprint)
            
    return (guard_group, exit_group)
    
    
def print_groups(initial_guards, exits_tot_bw, guard_group, exit_group):
    print('Guard group')
    print('Probability\tUptime\tFingerprint\tNickname')
    tot_prob = 0
    for fprint in guard_group:
        guard = initial_guards[fprint]
        tot_prob += guard['prob']
        print('{0}\t{1}\t{2}\t{3}'.format(guard['prob'], guard['uptime'],\
            fprint, guard['rel_stat'].nickname))
    print('Total prob: {0}\n'.format(tot_prob))
    print('Exit group')
    tot_cum_prob = 0
    tot_max_prob = 0
    tot_min_prob = 0
    print('Cum. prob\tMax prob\tMin prob\tFingerprint\tNickname')
    for fprint in exit_group:
        exit = exits_tot_bw[fprint]
        tot_cum_prob += exit['tot_bw']
        tot_max_prob += exit['max_prob']
        tot_min_prob += exit['min_prob']
        print('{0}\t{1}\t{2}\t{3}\t{4}'.format(exit['tot_bw'],\
            exit['max_prob'], exit['min_prob'], fprint, exit['nickname']))
    print('Total cumulative prob: {0}'.format(tot_cum_prob))
    print('Total max prob: {0}'.format(tot_max_prob))
    print('Total min prob: {0}'.format(tot_min_prob))    

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
    
    
def get_guard_bws_helper(ns_file):
    """Returns lists of guard bandwidths."""
    
    cons_rel_stats = {}    
    with open(ns_file, 'rb') as nsf:
        consensus = pickle.load(nsf)
        descriptors = pickle.load(nsf)
        
    for relay in consensus.routers:
        if (relay in descriptors):
            cons_rel_stats[relay] = consensus.routers[relay]
                
    guards_cons_bws = []
    guards_obs_bws = []
    # get guards
    guards = filter_guards(cons_rel_stats, descriptors)
    # add in circuit requirements (what guard_filter_for_circ would do)
    # because we don't have a circuit it mind, this is just a FAST flag
    for fprint in guards:
        rel_stat = cons_rel_stats[fprint]
        if (stem.Flag.FAST in rel_stat.flags):
            guards_cons_bws.append(cons_rel_stats[fprint].bandwidth)
            guards_obs_bws.append(descriptors[fprint].observed_bandwidth)
    return (guards_cons_bws, guards_obs_bws)    


def get_exit_bws_helper(ns_file):
    """Returns lists of exits bandwidths."""
    need_fast = True
    need_stable = False
    need_internal = False    
    
    
    cons_rel_stats = {}    
    with open(ns_file, 'rb') as nsf:
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
    

def map_files(in_dir, map_files_map_fn, num_processes):
    """Applies map_files_map_fn to files in in_dir using num_processes in
     parallel and returns array of results. Results assumed to be two lists.
     Useful for getting all consensus and observed bandwidths from network
    state files for later regression.
    Inputs:
        in_dir: directory containing network state files to examine
        map_files_map_fn: function taking filename and returning some a pair
            of sequences
        num_processes: number of processes to simultaneously process files"""
        
    network_state_files = []
    for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
        for filename in filenames:
            if (filename[0] != '.'):
                network_state_files.append(os.path.join(dirpath,filename))
    
    network_state_files.sort(key = lambda x: os.path.basename(x))
    cons_bws = []
    obs_bws = []    
    
    chunksize = int(math.floor(float(len(network_state_files)) /\
        num_processes))
    pool = multiprocessing.Pool(num_processes)
    process_bws = pool.map(map_files_map_fn, network_state_files, chunksize)
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
        cons_bws.extend(process_cons_bws)
        obs_bws.extend(process_obs_bws)
    print('len(cons_bws): {0}'.format(len(cons_bws)))
    print('len(obs_bws): {0}'.format(len(obs_bws)))    
    print('First elements: {0}; {1}'.format(cons_bws[0],
        obs_bws[0]))
    return (cons_bws, obs_bws)
    
    
def get_guard_regression(in_dir, num_processes):
    """Uses exit relay to calculate regression coefficients for
    consensus bandwidth to observed bandwidth."""

    (guards_cons_bws, guards_obs_bws) =  map_files(in_dir, 
        get_guard_bws_helper, num_processes)
    (a, b, r_squared) = linear_regression(guards_cons_bws,
        guards_obs_bws)
        
    return (a, b, r_squared)
    

def get_exit_regression(in_dir, num_processes):
    """Uses exit relay to calculate regression coefficients for
    consensus bandwidth to observed bandwidth."""

    (exits_cons_bws, exits_obs_bws) =  map_files(in_dir, get_exit_bws_helper,
        num_processes)
    (a, b, r_squared) = linear_regression(exits_cons_bws,
        exits_obs_bws)
        
    return (a, b, r_squared)


if __name__ == '__main__':
    # get guard bandwidth and cons->actual conversion for 3/1/13 guards
    (needed_cons_bw, needed_bw, guard_a, guard_b, guard_r_squared) =\
        find_needed_guard_bws()
### Output:
### a = 299.45192815560563
### b = 1104612.6683457776
### r_squared = 0.74124917207592156
### needed_cons_bw = 365924.087681159
### needed_bw = 110681286.28304975
    
    # get exit bandwidth conversion for 1/13-3/13
    in_dir = 'out/network-state/fat/ns-2013-01--03'    
    (exit_a, exit_b, exit_r_squared) = get_exit_regression(in_dir, 20)
    print('a = {0}'.format(exit_a))
    print('b = {0}'.format(exit_b))
    print('r^2 = {0}'.format(exit_r_squared))
### Output:
### a = 215.85762129136413
### b = 1010231.1684564484
### r_squared = 0.68600871839386535

    # get exit bandwidth conversion for 10/12-3/13
    in_dir = 'out/network-state/fat/ns-2012-10--2013-03'    
    (exit_a, exit_b, exit_r_squared) = get_exit_regression(in_dir, 20)
    print('a = {0}'.format(exit_a))
    print('b = {0}'.format(exit_b))
    print('r^2 = {0}'.format(exit_r_squared))
### Output:    
# Number of individual bw lists: 4358
# Max cons bw list length: 1076
# Max obs bw list length: 1076
# Min cons bw list length: 777
# Min obs bw list length: 777
# len(exits_cons_bws): 3818707
# len(exits_obs_bws): 3818707
# First elements: 30; 77313
# exit_a = 200.49050736264786
# exit_b = 1029509.7491675143
# exit_r_squared = 0.69361698646482162

    # get guard bandwidth conversion for 10/12-3/13
    in_dir = 'out/network-state/fat/ns-2012-10--2013-03'
    (guard_a, guard_b, guard_r_squared) = get_guard_regression(in_dir, 20)
### Output:
# Number of individual bw lists: 4358
# Max cons bw list length: 1665
# Max obs bw list length: 1665
# Min cons bw list length: 716
# Min obs bw list length: 716
# len(cons_bws): 4120356
# len(obs_bws): 4120356
# First elements: 460; 290137
# guard_a = 191.94548955003913
# guard_b = 1368281.674385923
# guard_r_squared = 0.70610513990802581
