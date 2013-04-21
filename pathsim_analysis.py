import sys
import os
import stem
import cPickle as pickle
from pathsim import *
#import numpy
#import matplotlib
#matplotlib.use('PDF')
#import matplotlib.pyplot
##import matplotlib.mlab
#import math
import multiprocessing


def compromised_set_process_log(compromised_relays, out_dir, out_name,\
    pnum, log_file):
    """Calculates security statistics against compromised-set
    adversary and outputs the results to a file."""
    compromise_stats = []
    start_time = None
    end_time = None
    with open(log_file, 'r') as lf:
        lf.readline() # read header line
#        i = 0
        for line in lf:
#            if (i % 5000 == 0):
#                print('Read {0} lines.'.format(i))
#            i = i+1
            line = line[0:-1] # cut off final newline
            line_fields = line.split('\t')
            id = int(line_fields[0])
            time = float(line_fields[1])
            guard_ip = line_fields[2]
            exit_ip = line_fields[4]

            # add entries for sample not yet seen
            if (len(compromise_stats) <= id):
                for i in xrange(id+1 - len(compromise_stats)):
                    stats = {'guard_only_bad':0,\
                                'exit_only_bad':0,\
                                'guard_and_exit_bad':0,\
                                'good':0,\
                                'guard_only_time':None,\
                                'exit_only_time':None,\
                                'guard_and_exit_time':None}
                    compromise_stats.append(stats)
                    
            # update start and end times
            if (start_time == None):
                start_time = time
            else:
                start_time = min(start_time, time)
            if (end_time == None):
                end_time = time
            else:
                end_time = max(end_time, time)
                    
            # increment counts and add times of first compromise
            stats = compromise_stats[id]
            guard_bad = guard_ip in compromised_relays
            exit_bad = exit_ip in compromised_relays
            if  (guard_bad and exit_bad):
                stats['guard_and_exit_bad'] += 1
                if (stats['guard_and_exit_time'] == None):
                    stats['guard_and_exit_time'] = time
                else:
                    stats['guard_and_exit_time'] = \
                        min(time, stats['guard_and_exit_time'])
            elif guard_bad:
                stats['guard_only_bad'] += 1
                if (stats['guard_only_time'] == None):
                    stats['guard_only_time'] = time
                else:
                    stats['guard_only_time'] = \
                        min(time, stats['guard_only_time'])
            elif exit_bad:
                stats['exit_only_bad'] += 1
                if (stats['exit_only_time'] == None):
                    stats['exit_only_time'] = time
                else:
                    stats['exit_only_time'] = \
                        min(time, stats['exit_only_time'])                        
            else:
                stats['good'] += 1

    out_filename = 'analyze-sim.' + out_name + '.' + str(pnum) + '.pickle'
    out_pathname = os.path.join(out_dir, out_filename)
    with open(out_pathname, 'wb') as f:
        pickle.dump(start_time, f, pickle.HIGHEST_PROTOCOL)
        pickle.dump(end_time, f, pickle.HIGHEST_PROTOCOL)
        pickle.dump(compromise_stats, f, pickle.HIGHEST_PROTOCOL)
    

def compromised_top_relays_process_log(top_guards, top_exits, out_dir,\
    out_name, pnum, log_file):
    """Calculates security statistics against top-relay
    adversary and stores the results in a Process.Queue."""
    compromise_stats = []
    start_time = None
    end_time = None
    with open(log_file, 'r') as lf:
        lf.readline() # read header line
#        i = 0
        for line in lf:
#            if (i % 5000 == 0):
#                print('Read {0} lines.'.format(i))
#            i = i+1
            line = line[0:-1] # cut off final newline
            line_fields = line.split('\t')
            id = int(line_fields[0])
            time = float(line_fields[1])
            guard_ip = line_fields[2]
            exit_ip = line_fields[4]
                    
            """Adds statistics based on fields from log line."""
            # add entries for sample not yet seen
            if (len(compromise_stats) <= id):
                for i in xrange(id+1 - len(compromise_stats)):
                    # matrix storing counts for possible # comp relays
                    stats = []
                    for j in xrange(len(top_guards)+1):
                        stats.append([])
                        for k in xrange(len(top_exits)+1):
                            stats[j].append({'guard_only_bad':0,\
                                            'exit_only_bad':0,\
                                            'guard_and_exit_bad':0,\
                                            'good':0,\
                                            'guard_only_time':None,\
                                            'exit_only_time':None,\
                                            'guard_and_exit_time':None})
                    compromise_stats.append(stats)
                    
                    
            # update start and end times
            if (start_time == None):
                start_time = time
            else:
                start_time = min(start_time, time)
            if (end_time == None):
                end_time = time
            else:
                end_time = max(end_time, time)

            # find first occurrence of guard_ip and exit_ip in top_guards
            # and top_exits - .index() would raise error if not present
            top_guards_guard_idx = None
            top_guards_exit_idx = None
            top_exits_guard_idx = None
            top_exits_exit_idx = None
            for i, top_guard in enumerate(top_guards):
                if (guard_ip == top_guard):
                    top_guards_guard_idx = i+1
                    break
            for i, top_guard in enumerate(top_guards):
                if (exit_ip == top_guard):
                    top_guards_exit_idx = i+1
                    break                
            for i, top_exit in enumerate(top_exits):
                if (guard_ip == top_exit):
                    top_exits_guard_idx = i+1
                    break
            for i, top_exit in enumerate(top_exits):
                if (exit_ip == top_exit):
                    top_exits_exit_idx = i+1
                    break    
                    
            # increment counts and add times of first compromise
            for i in xrange(len(compromise_stats[id])):
                for j in xrange(len(compromise_stats[id][i])):
                    stats = compromise_stats[id][i][j]
                    guard_bad = False
                    exit_bad = False
                    if ((top_guards_guard_idx != None) and\
                            (top_guards_guard_idx <= i)) or\
                        ((top_exits_guard_idx != None) and\
                             (top_exits_guard_idx <= j)):
                        guard_bad = True
                    if ((top_guards_exit_idx != None) and\
                            (top_guards_exit_idx <= i)) or\
                        ((top_exits_exit_idx != None) and\
                            (top_exits_exit_idx <= j)):
                        exit_bad = True
    
                    if  (guard_bad and exit_bad):
                        stats['guard_and_exit_bad'] += 1
                        if (stats['guard_and_exit_time'] == None):
                            stats['guard_and_exit_time'] = time
                        else:
                            stats['guard_and_exit_time'] = \
                                min(time, stats['guard_and_exit_time'])
                    elif guard_bad:
                        stats['guard_only_bad'] += 1
                        if (stats['guard_only_time'] == None):
                            stats['guard_only_time'] = time
                        else:
                            stats['guard_only_time'] = \
                                min(time, stats['guard_only_time'])
                    elif exit_bad:
                        stats['exit_only_bad'] += 1
                        if (stats['exit_only_time'] == None):
                            stats['exit_only_time'] = time
                        else:
                            stats['exit_only_time'] = \
                                min(time, stats['exit_only_time'])                        
                    else:
                        stats['good'] += 1

    out_filename = 'analyze-sim.' + out_name + '.' + str(pnum) + '.pickle'
    out_pathname = os.path.join(out_dir, out_filename)
    with open(out_pathname, 'wb') as f:
        pickle.dump(start_time, f, pickle.HIGHEST_PROTOCOL)
        pickle.dump(end_time, f, pickle.HIGHEST_PROTOCOL)
        pickle.dump(compromise_stats, f, pickle.HIGHEST_PROTOCOL)


def compromised_top_relays_print(in_file, top_guards, top_exits):
    """Print stats from output of compromised_top_relays_process_log().""" 
    
    with open(in_file, 'rb') as f:
        start_time = pickle.load(f)
        end_time = pickle.load(f)
        compromise_stats = pickle.load(f)
    
    # only write stats for powers of two adversaries
    num_guards = 0
    while (num_guards <= len(top_guards)):
        if (num_guards == 0):
            num_exits = 1
        else:
            num_exits = 0
        while (num_exits <= len(top_exits)):
            print('#\tbad guard&exit\tbad guard only\tbad exit only\tgood\tguard&exit time\tguard only time\texit only time')
            for i, comp_stats in enumerate(compromise_stats):
                adv_stats = comp_stats[num_guards][num_exits]
                if (adv_stats['guard_and_exit_time'] != None):
                    ge_time = adv_stats['guard_and_exit_time']
                else:
                    ge_time = -1
                if (adv_stats['guard_only_time'] != None):
                    g_time = adv_stats['guard_only_time']
                else:
                    g_time = -1
                if (adv_stats['exit_only_time'] != None):
                    e_time = adv_stats['exit_only_time']
                else:
                    e_time = -1                                                        
                f.write('{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}\n'.\
                    format(i, adv_stats['guard_and_exit_bad'],\
                        adv_stats['guard_only_bad'],\
                        adv_stats['exit_only_bad'],\
                        adv_stats['good'],\
                        ge_time, g_time, e_time))
            if (num_exits == 0):
                num_exits = 1
            else:
                num_exits *= 2
        if (num_guards == 0):
            num_guards = 1
        else:
            num_guards *= 2
        
        
def network_analysis_get_guards_and_exits(network_state_files, ip, port):
    """Takes list of network state files, pads the sorted list for missing
    periods, and returns selection statistics about initial guards and
    exits."""
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
            # also turn cumulative probs into individual ones
            cum_weight_old = 0
            for fprint, cum_weight in cum_weighted_guards:
                rel_stat = cons_rel_stats[fprint]
                if ((not need_fast) or (stem.Flag.FAST in rel_stat.flags)) and\
                   ((not need_stable) or (stem.Flag.STABLE in rel_stat.flags)):
                   desc = descriptors[fprint]
                   initial_guards[fprint] = {\
                    'rel_stat':rel_stat,\
                    'prob':cum_weight-cum_weight_old,\
                    'uptime':1,
                    'tot_average_bandwidth':desc.average_bandwidth,\
                    'tot_burst_bandwidth':desc.burst_bandwidth,\
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
                    

        # get relays that exit to our dummy dest ip and port
        # with sum of weighted selection probabilities
        weighted_exits = get_weighted_exits(cons_bw_weights,\
            cons_bwweightscale, cons_rel_stats, descriptors, need_fast, \
            need_stable, need_internal, ip, port)
        cum_weight_old = 0
        for fprint, cum_weight in weighted_exits:
            if fprint not in exits_tot_bw:
                exits_tot_bw[fprint] =\
                    {'tot_bw':0,\
                    'nickname':cons_rel_stats[fprint].nickname,\
                    'max_prob':0,\
                    'min_prob':1,\
                    'tot_cons_bw':0,\
                    'tot_average_bandwidth':0,\
                    'tot_burst_bandwidth':0,\
                    'tot_observed_bandwidth':0,\
                    'uptime':0}
            prob = cum_weight - cum_weight_old
            exits_tot_bw[fprint]['tot_bw'] += prob
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
    

def network_analysis_print_guards_and_exits(initial_guards, exits_tot_bw,\
    guard_cum_prob, num_exits, ip, port):
    """Prints top initial guards comprising [guard_cum_prob] selection prob.
    and top [num_exits] exits."""
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
            avg_observed_bw, fp, guard['rel_stat'].nickname))
        cum_prob += guard['prob']
        i += 1

    # print out top exits by total probability-weighted uptime
    exits_tot_bw_sorted = exits_tot_bw.items()
    exits_tot_bw_sorted.sort(key = lambda x: x[1]['tot_bw'], reverse=True)
    i = 1
    print('Top {0} exits to {1}:{2} by probability-weighted uptime'.\
        format(num_exits, ip, port))
    print('#\tCum. prob.\tMax prob.\tMin prob.\tAvg. Cons. BW\tAvg. Avg. BW\tAvg. Observed BW\tUptime\tFingerprint\t\t\t\t\t\t\tNickname')
    for fprint, bw_dict in exits_tot_bw_sorted[0:num_exits]:
        avg_cons_bw = float(bw_dict['tot_cons_bw']) / float(bw_dict['uptime'])
        avg_average_bw = float(bw_dict['tot_average_bandwidth'])/\
            float(bw_dict['uptime'])
        avg_observed_bw = float(bw_dict['tot_observed_bandwidth'])/\
            float(bw_dict['uptime'])
        print(\
        '{0}\t{1:.4f}\t{2:.4f}\t{3:.4f}\t{4:.4f}\t{5:.4f}\t{6:.4f}\t{7}\t{8}\t{9}'.\
            format(i, bw_dict['tot_bw'], bw_dict['max_prob'],\
                bw_dict['min_prob'], avg_cons_bw, avg_average_bw,\
                avg_observed_bw, bw_dict['uptime'], fprint,\
                bw_dict['nickname']))
        i += 1
        
        
def network_analysis_get_groups(initial_guards, exits_tot_bw,\
    guard_substr, exit_substr):
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
    
    
def network_analysis_print_groups(initial_guards, exits_tot_bw,\
    guard_group, exit_group):
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


def simulation_analysis(log_files, process_log, process_log_args):
    """Runs log file fields through given adversary object.
        Inputs:
            log_files: list of log files
            adv: adversary object containing processing methods
    """
    ps = []
    i = 1
    for log_file in log_files:        
        print('Processing file {0}.'.format(os.path.basename(log_file)))
        p = multiprocessing.Process(target=process_log, \
            args = process_log_args + (i, log_file))
        p.start()
        ps.append(p)
        i += 1
    print('len(ps): {0}'.format(len(ps)))
    i = 1
    for p in ps:
        print('Waiting for process')
        p.join()
        print('Process {0} returned.'.format(i))
        i += 1
        
def read_compromised_relays_file(in_file):
    """Parse file containing compromised relays."""
    compromised_relays = []
    with open(in_file) as f:
        for line in f:
            line = line.strip()
            if (line[0] == '#'):
                continue
            compromised_relays.append(line)
    return compromised_relays


if __name__ == '__main__':
    usage = 'Usage: pathsim_analysis.py [command]\nCommands:\n\
\tnetwork [in_dir]:  Analyze the network status files in in_dir.\n\
\tsimulation-set [logs_in_dir] [set_in_file] [out_dir] [out_name]: Do analysis against compromised set. Use simulation logs in logs_in_dir and IPs in set_in_file, and write statistics to files in out_dir in files with names containing out_name.\n\
\tsimulation-top [logs_in_dir] [top_guards_in_file] [top_exits_in_file] [out_dir] [out_name]: Do analysis\
against adversary compromising a range of top guards and exits.'
    if (len(sys.argv) < 2):
        print(usage)
        sys.exit(1)
        
    command = sys.argv[1]
    if (command != 'network') and (command != 'simulation-set') and\
        (command != 'simulation-top'):
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
        ip = '74.125.131.105'
        port = 80
        guard_cum_prob = 0.5
        num_exits = 50
        (initial_guards, exits_tot_bw) = \
            network_analysis_get_guards_and_exits(network_state_files, ip,\
                port)
        network_analysis_print_guards_and_exits(initial_guards, exits_tot_bw,\
            guard_cum_prob, num_exits, ip, port)

        # some group substrings that have been of interest            
        guard_substr = 'TORy'    
        #guard_substr = 'PPrivCom'
        #guard_substr = 'chaoscomputerclub'
        exit_substr = 'chaoscomputerclub'
        #exit_substr = 'TorLand'
        #exit_substr = 'noiseexit'
        (guard_group, exit_group) = network_analysis_get_groups(\
            initial_guards, exits_tot_bw, guard_substr, exit_substr)
        network_analysis_print_groups(initial_guards, exits_tot_bw,\
            guard_group, exit_group)
            
    elif (command == 'simulation-set'):
        if (len(sys.argv) < 6):
            print(usage)
            sys.exit(1)
            
        # get list of log files
        in_dir = sys.argv[2]
        in_file = sys.argv[3]
        out_dir = sys.argv[4]
        out_name = sys.argv[5]
        log_files = []
        for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
            for filename in filenames:
                if (filename[0] != '.'):
                    log_files.append(os.path.join(dirpath,filename))
        log_files.sort(key = lambda x: os.path.basename(x))
        
        compromised_relays = read_compromised_relays_file(in_file)
        args = (compromised_relays, out_dir, out_name)
        simulation_analysis(log_files, compromised_set_process_log, args)
        
    elif (command == 'simulation-top'):
#simulation-top [logs_in_dir] [top_guards_in_file] [top_exits_in_file] [out_dir] [out_name]    
        if (len(sys.argv) < 7):
            print(usage)
            sys.exit(1)
            
        # get list of log files
        in_dir = sys.argv[2]
        guards_in_file = sys.argv[3]
        exits_in_file = sys.argv[4]
        out_dir = sys.argv[5]
        out_name = sys.argv[6]
        log_files = []
        for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
            for filename in filenames:
                if (filename[0] != '.'):
                    log_files.append(os.path.join(dirpath,filename))
        log_files.sort(key = lambda x: os.path.basename(x))

        top_guard_ips = read_compromised_relays_file(guards_in_file)
        top_exit_ips = read_compromised_relays_file(exits_in_file)
                
        args = (top_guard_ips, top_exit_ips, out_dir, out_name)
        simulation_analysis(log_files, compromised_top_relays_process_log,\
            args)