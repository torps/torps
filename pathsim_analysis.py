import sys
import os
import cPickle as pickle
from pathsim import *
#import numpy
#import matplotlib
#matplotlib.use('PDF')
#import matplotlib.pyplot
##import matplotlib.mlab
#import math
import multiprocessing
#import network_analysis
import re


def compromised_set_get_compromise_rates(pathnames):
    """Takes output of pathsim_analysis.compromised_set_process_log()
    and return the fraction of *streams* (among all samples) that have
    guard/exit/guard+exit compromise."""      
    num_streams = 0
    num_guard_compromised = 0
    num_exit_compromised = 0
    num_guard_exit_compromised = 0
    for pathname in pathnames:
        with open(pathname) as f:
            print('Processing {0}.'.format(pathname))
            start_time = pickle.load(f)
            end_time = pickle.load(f)
            compromise_stats = pickle.load(f)
            for stats in compromise_stats:
                num_streams += stats['guard_only_bad'] +\
                    stats['exit_only_bad'] + stats['guard_and_exit_bad'] +\
                    stats['good']
                num_guard_compromised += stats['guard_only_bad'] +\
                    stats['guard_and_exit_bad']
                num_exit_compromised += stats['exit_only_bad'] +\
                    stats['guard_and_exit_bad']
                num_guard_exit_compromised += stats['guard_and_exit_bad']
    print('Num streams: {0}'.format(num_streams))
    return (float(num_guard_compromised)/num_streams,
        float(num_exit_compromised)/num_streams,
        float(num_guard_exit_compromised)/num_streams)

def compromised_set_get_compromise_probs(pathnames):
    """Takes output of pathsim_analysis.compromised_set_process_log()
    and return the fraction of  samples that experience at least one
    guard/exit/guard+exit compromise."""      
    num_samples = 0
    num_guard_compromised = 0
    num_exit_compromised = 0
    num_guard_exit_compromised = 0
    for pathname in pathnames:
        with open(pathname) as f:
            print('Processing {0}.'.format(pathname))
            start_time = pickle.load(f)
            end_time = pickle.load(f)
            compromise_stats = pickle.load(f)
            for stats in compromise_stats:
                num_samples += 1
                if (stats['guard_only_time'] != None) or\
                    (stats['guard_and_exit_time'] != None):
                    num_guard_compromised += 1
                if (stats['exit_only_time'] != None) or\
                    (stats['guard_and_exit_time'] != None):
                    num_exit_compromised += 1
                if (stats['guard_and_exit_time'] != None):
                    num_guard_exit_compromised += 1
    print('Num samples: {0}'.format(num_samples))
    return (float(num_guard_compromised)/num_samples,
        float(num_exit_compromised)/num_samples,
        float(num_guard_exit_compromised)/num_samples)
        

def compromised_set_process_log(compromised_relays, out_dir, out_name, format,
    pnum, log_file):
    """Calculates security statistics against compromised-set
    adversary and outputs the results to a file.
    If format is 'relay-adv', a compact format just indicating
    guard/exit compromise is assumed.
    """
    compromise_stats = []
    start_time = None
    end_time = None
    with open(log_file, 'r') as lf:
        line = lf.readline() # read header line
#        i = 0
        for line in lf:
#            if (i % 5000 == 0):
#                print('Read {0} lines.'.format(i))
#            i = i+1
            if line[0]=='#':
                continue

            line = line[0:-1] # cut off final newline
#            line_fields = line.split('\t')
            line_fields = re.split('\t|\s+',line)    
            id = int(line_fields[0])
            time = float(line_fields[1])
            if (format == 'relay-adv'):
                compromise_code = int(line_fields[2])
            else:
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
            if (format == 'relay-adv'):
                guard_bad = (compromise_code == 1) or (compromise_code == 3)
                exit_bad = (compromise_code == 2) or (compromise_code == 3)
            else:
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
\tsimulation-set [logs_in_dir] [out_dir] [out_name] [set_in_file]: Do analysis against \
compromised set. Use simulation logs in logs_in_dir and IPs in set_in_file, and write \
statistics to files in out_dir in files with names containing out_name. If set_in_file \
omitted, the compact "relay-adv" format is expected.\n\
\tsimulation-top [logs_in_dir] [top_guards_in_file] [top_exits_in_file] [out_dir] \
[out_name]: Do analysis against adversary compromising a range of top guards and exits.'
    if (len(sys.argv) < 2):
        print(usage)
        sys.exit(1)
        
    command = sys.argv[1]
    if (command != 'simulation-set') and (command != 'simulation-top'):
        print(usage)
            
    elif (command == 'simulation-set'):
        if (len(sys.argv) < 5):
            print(usage)
            sys.exit(1)
            
        # get list of log files
        in_dir = sys.argv[2]
        out_dir = sys.argv[3]
        out_name = sys.argv[4]
        in_file = sys.argv[5] if (len(sys.argv) > 5) else None
        log_files = []
        for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
            for filename in filenames:
                if (filename[0] != '.'):
                    log_files.append(os.path.join(dirpath,filename))
        log_files.sort(key = lambda x: os.path.basename(x))
        
        if (in_file != None):
            compromised_relays = read_compromised_relays_file(in_file)
            format = 'normal'
        else:
            compromised_relays = None
            format = 'relay-adv'
        args = (compromised_relays, out_dir, out_name, format)
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