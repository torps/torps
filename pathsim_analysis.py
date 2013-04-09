import sys
import os
import stem
import cPickle as pickle
from pathsim import *

def network_analysis(network_state_files):
    """Prints large guards and exits in consensuses over the time period covered by the input \
    files."""
    
    network_state_files = pad_network_state_files(network_state_files)
    initial_guards = []
    exits_tot_bw = {} # rel_stat -> sum of hours active weighted by exit prob.
    
    need_fast = True
    need_stable = False
    need_internal = False
    ip = '74.125.131.105'
    port = 80

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
                hibernating_status = {}
                
                # set variables from consensus
                cons_valid_after = timestamp(consensus.valid_after)            
                cons_fresh_until = timestamp(consensus.fresh_until)
                cons_bw_weights = consensus.bandwidth_weights
                if (consensus.bwweightscale == None):
                    cons_bwweightscale = 10000
                else:
                    cons_bwweightscale = consensus.bwweightscale
                for relay in consensus.relays:
                    if (relay in descriptors):
                        cons_rel_stats[relay] = consensus.relays[relay]
        else:
            if (cons_valid_after == None) or (cons_fresh_until == None):
                raise ValueError('Network status files begin with "None".')
            # gap in consensuses, just advance an hour, keeping network state            
            cons_valid_after += 3600
            cons_fresh_until += 3600
            # set empty statuses, even though previous should have been emptied
            hibernating_statuses = []
            
        # don't maintain or use hibernating statuses for now
        # just add initial entry guards sorted by probability
        # and add probability to relays that exit to our dummy dest ip and port
        if init:
            init = False
            guards = filter_guards(cons_rel_stats, descriptors)
            guard_weights = get_position_weights(guards,\
                cons_rel_stats, 'g', cons_bw_weights, cons_bwweightscale)
            cum_weighted_guards = get_weighted_nodes(guards,\
                guard_weights)
            # add in circuit requirements (what guard_filter_for_circ would do)
            # also turn cumulative probs into individual ones
            cum_weight_old = 0
            for fprint, cum_weight in cum_weighted_guards:
                rel_stat = cons_rel_stats[fprint]
                if ((not need_fast) or (stem.Flag.FAST in rel_stat.flags)) and\
                   ((not need_stable) or (stem.Flag.STABLE in rel_stat.flags)):
                   initial_guards.append((rel_stat, cum_weight-cum_weight_old))
                cum_weight_old = cum_weight
        """
        weighted_exits = get_weighted_exits(cons_bw_weights,\
            cons_bwweightscale, cons_rel_stats, descriptors, need_fast, \
            need_stable, need_internal, ip, port)
        cum_weight_old = 0
        for fprint, cum_weight in weighted_exits:
            if fprint not in exits_tot_bw:
                exits_tot_bw[fprint] = 0
            exits_tot_bw[fprint] += cum_weight - cum_weight_old
            cum_weight_old = cum_weight
        """

    # print out top initial guards comprising 20% total selection prob.
    initial_guards.sort(key = lambda x: x[1], reverse=True)
    cum_prob = 0
    print('Top initial guards comprising 20% total selection probability')
    for guard in initial_guards:
        if (cum_prob >= 0.2):
            break
        rel_stat = guard[0]
        print('{0} [{1}]: {2}'.format(guard[0].nickname, guard[0].fingerprint,\
            guard[1]))
        cum_prob += guard[1]

    # print out top exits by total probability-weighted uptime
    exits_tot_bw_sorted = exits_tot_bw.items().sort(key = lambda x: x[1])
    print('Top 20 exits to {0}:{1} by probability-weighted uptime'.\
        format(ip, port))
    for fprint, bw in exits_tot_bw_sorted:
        rel_stat = cons_rel_stats[fprint]
        print('{0} [{1}]: {2}'.format(rel_stat.nickname, fprint, bw))

if __name__ == '__main__':
    usage = 'Usage: pathsim_analysis.py [command]\nCommands:\n\
\tnetwork [in_dir]:  Do some analysis on the network status files in in_dir.\n\
\tsimulation [in_dir]: Do some analysis on the simulation logs in in_dir.'
    if (len(sys.argv) <= 1):
        print(usage)
        sys.exit(1)
        
    command = sys.argv[1]
    if (command != 'network') and (command != 'simulation'):
        print(usage)
    elif (command == 'network'):
        if (len(sys.argv) < 3):
            print(usage)
            sys.exit(1)
        in_dir = sys.argv[2]
        print('in_dir: {0}'.format(in_dir))
        
        network_state_files = []
        for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
            for filename in filenames:
                if (filename[0] != '.'):
                    network_state_files.append(os.path.join(dirpath,filename))
        network_state_files.sort(key = lambda x: os.path.basename(x))
        network_analysis(network_state_files)
    elif (command == 'simulation'):
        if (len(sys.argv) < 3):
            print(usage)
            sys.exit(1)
        in_dir = sys.argv[2]