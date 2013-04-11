import sys
import os
import stem
import cPickle as pickle
from pathsim import *

def network_analysis(network_state_files):
    """Prints large guards and exits in consensuses over the time period covered by the input \
    files."""
    
    network_state_files = pad_network_state_files(network_state_files)
    initial_guards = {}
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
            print('Filling in gap from {0} to {1}'.format(cons_valid_after,\
                cons_fresh_until))
            # set empty statuses, even though previous should have been emptied
            hibernating_statuses = []
            
        # don't maintain or use hibernating statuses for now
        
        # get initial entry guards with selection probability and their uptime
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
                   initial_guards[fprint] = {\
                    'rel_stat':rel_stat,\
                    'prob':cum_weight-cum_weight_old,\
                    'uptime':0}
                cum_weight_old = cum_weight
        else:
            # apply criteria used in setting bad_since
            for guard in initial_guards:
                if (guard in cons_rel_stats) and\
                    (stem.Flag.RUNNING in cons_rel_stats[guard].flags) and\
                    (stem.Flag.GUARD in cons_rel_stats[guard].flags):
                    initial_guards[guard]['uptime'] += 1

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
                    'nickname':cons_rel_stats[fprint].nickname,
                    'max_prob':0,
                    'min_prob':1}
            prob = cum_weight - cum_weight_old
            exits_tot_bw[fprint]['tot_bw'] += prob
            exits_tot_bw[fprint]['max_prob'] = \
                max(exits_tot_bw[fprint]['max_prob'], prob)
            exits_tot_bw[fprint]['min_prob'] = \
                min(exits_tot_bw[fprint]['min_prob'], prob)                
            cum_weight_old = cum_weight

    # print out top initial guards comprising some total selection prob.
    initial_guards_items = initial_guards.items()
    initial_guards_items.sort(key = lambda x: x[1]['prob'], reverse=True)
    cum_prob = 0
    i = 1    
    print('Top initial guards comprising 50% total selection probability')
    print('#\tProb.\tUptime\tFingerprint\t\t\t\t\t\t\tNickname')
    for fp, guard in initial_guards_items:
        if (cum_prob >= 0.5):
            break
        print('{0}\t{1:.4f}\t{2}\t{3}\t{4}'.format(i, guard['prob'], \
            guard['uptime'], fp, guard['rel_stat'].nickname))
        cum_prob += guard['prob']
        i += 1

    # print out top exits by total probability-weighted uptime
    exits_tot_bw_sorted = exits_tot_bw.items()
    exits_tot_bw_sorted.sort(key = lambda x: x[1]['tot_bw'], reverse=True)
    i = 1
    print('Top 50 exits to {0}:{1} by probability-weighted uptime'.\
        format(ip, port))
    print('#\ttot_bw\tmax_pr\tmin_pr\tFingerprint\t\t\t\t\t\t\tNickname')
    for fprint, bw_dict in exits_tot_bw_sorted[0:50]:
        print('{0}\t{1:.4f}\t{2:.4f}\t{3:.4f}\t{4}\t{5}'.\
            format(i, bw_dict['tot_bw'], bw_dict['max_prob'],\
                bw_dict['min_prob'], fprint, bw_dict['nickname']))
        i += 1
        
        
def simulation_analysis(log_files, malicious_ips):
    """Returns times to first to compromise and compromise counts for all samples."""
    print('test')
    all_times_to_first_compromise = []
    all_compromise_counts = []
    for log_file in log_files:
        compromise_times = []
        compromise_counts = []        
        
        with open(log_file, 'r') as lf:
            print('Processing file {0}.'.format(os.path.basename(log_file)))
            lf.readline() # read header line
            i = 0
            for line in lf:
                if (i % 1000000 == 0):
                    print('Read {0} lines.'.format(i))
                i = i+1

                line = line[0:-1] # cut off final newline
                line_fields = line.split('\t')
                id = int(line_fields[0])
                time = int(line_fields[1])
                guard_ip = line_fields[2]
                exit_ip = line_fields[4]
                
                # add extra empty stats slots if needed
                if (len(compromise_times) <= id):
                    compromise_times[len(compromise_times):] = \
                        [None]*(id+1 - len(compromise_times))
                if (len(compromise_counts) <= id):
                    for j in range(id+1 - len(compromise_counts)):
                        compromise_counts.append(\
                            {'guard_only_bad':0,\
                            'exit_only_bad':0,\
                            'guard_and_exit_bad':0,\
                            'good':0})
                            
                if (guard_ip in malicious_ips) and (exit_ip in malicious_ips):
                    compromise_counts[id]['guard_and_exit_bad'] += 1
                    if (compromise_times[id] == None):
                        compromise_times[id] = time
                    else:
                        compromise_times[id] = min(time, compromise_times[id])
                elif (guard_ip in malicious_ips):
                    compromise_counts[id]['guard_only_bad'] += 1
                elif (exit_ip in malicious_ips):
                    compromise_counts[id]['exit_only_bad'] += 1
                else:
                    compromise_counts[id]['good'] += 1
        all_times_to_first_compromise.extend(compromise_times)
        all_compromise_counts.extend(compromise_counts)       
    return (all_times_to_first_compromise, all_compromise_counts)

if __name__ == '__main__':
    usage = 'Usage: pathsim_analysis.py [command]\nCommands:\n\
\tnetwork [in_dir]:  Analyze the network status files in in_dir.\n\
\tsimulation [in_dir] [out_dir]: Analyze the simulation logs in in_dir, write statistics to files in out_dir.'
    if (len(sys.argv) < 2):
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
        if (len(sys.argv) < 4):
            print(usage)
            sys.exit(1)
            
        # get list of log files
        in_dir = sys.argv[2]
        out_dir = sys.argv[3]
        log_files = []
        for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
            for filename in filenames:
                if (filename[0] != '.'):
                    log_files.append(os.path.join(dirpath,filename))
        log_files.sort(key = lambda x: os.path.basename(x))
        
        # get time of first circuit creation for each sample
        period_start_times(log_files)#START
        
        # set malicious ips (top guards/exits, determined manually)
        # 1        BigBoy              38.229.79.2
        # 2        ph3x                86.59.119.83
        # 3        TORy2               137.56.163.46
        # 4        TORy3               137.56.163.46  ## DUP!
        # 5        PPrivCom016         46.165.196.73
        # 6        oilsrv1             62.220.136.253
        # 7        OldPlanetExpress    85.214.75.110
        # 8        OnionsAndAtoms      18.85.8.71
        # 9        IDXFdotcomMinz      85.17.122.34
        # 10        TORy1               137.56.163.64
        top_guard_ips = ['38.229.79.2', '86.59.119.83', '137.56.163.46',\
            '46.165.196.73', '62.220.136.253', '85.214.75.110', '18.85.8.71',\
            '85.17.122.34', '137.56.163.64']
        # Top exits 3/12-4/12
        # 1        ZhangPoland1        178.217.184.147
        # 2        rainbowwarrior      77.247.181.164
        # 3        hazare              96.44.163.77
        # 4        TorLand1            146.185.23.179
        # 5        manning             173.254.192.36
        # 6        chomsky             77.247.181.162
        # 7        saeed               96.44.163.75
        # 8        wau                 109.163.233.200
        # 9        TorLand2            146.185.23.180
        # 10        chaoscomputerclub18 31.172.30.1
        top_exit_ips = ['178.217.184.147', '77.247.181.164', '96.44.163.77',\
            '146.185.23.179', '173.254.192.36', '77.247.181.162',\
            '96.44.163.75', '109.163.233.200', '146.185.23.180', '31.172.30.1']
        num_bad_guards = 4
        num_bad_exits = 4
        malicious_ips = top_guard_ips[0:num_bad_guards]
        malicious_ips.extend(top_exit_ips[0:num_bad_exits])
        (times_to_first_compromise, compromise_counts) = \
            simulation_analysis(log_files, malicious_ips)
        compromise_times_file = os.path.join(out_dir,\
            'analyze.XX--XX.compromise-times.{0}-{1}.out'.\
                format(num_bad_guards, num_bad_exits))
        compromise_counts_file = os.path.join(out_dir,\
            'analyze.XX--XX.compromise-counts.{0}-{1}.out'.\
                format(num_bad_guards, num_bad_exits))
        with open(compromise_times_file, 'w') as f:
            f.write('#\tTime of first compromise\n')
            for i, t in enumerate(times_to_first_compromise):
                if (t == None):
                    t = -1
                f.write('{0}\t{1}\n'.format(i,t))
        with open(compromise_counts_file, 'w') as f:
            f.write('#\tbad guard&exit\tbad guard\tbad exit\tgood\n')
            for i, cts in enumerate(compromise_counts):
                f.write('{0}\t{1}\t\t{2}\t\t{3}\t\t{4}\n'.format(i,\
                    cts['guard_and_exit_bad'], cts['guard_only_bod'],\
                    cts['exit_only_bad'], cts['good']))