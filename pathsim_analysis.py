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


##### Plotting functions #####
## helper - cumulative fraction for y axis
def cf(d): return numpy.arange(1.0,float(len(d))+1.0)/float(len(d))

## helper - return step-based CDF x and y values
## only show to the 99th percentile by default
def getcdf(data, shownpercentile=0.99):
    data.sort()
    frac = cf(data)
    x, y, lasty = [], [], 0.0
    for i in xrange(int(round(len(data)*shownpercentile))):
        x.append(data[i])
        y.append(lasty)
        x.append(data[i])
        y.append(frac[i])
        lasty = frac[i]
    return (x, y)
##########


class CompromisedSet:
    """
    Keeps statistics on circuit end compromises, where the adversary
    is a set of relays.
    """
    def __init__(self, compromised_relays):
        self.compromised_relays = compromised_relays
        self.all_compromise_stats = []
        self.start_time = None
        self.end_time = None
        
        
    def start(self):
        """Data from new log file will be processed."""
        self.compromise_stats = []        
        
        
    def end(self):
        """Store in final form stats collected from a log file."""
        self.all_compromise_stats.extend(self.compromise_stats)


    def log_line(self, id, time, guard_ip, exit_ip):
        # add entries for sample not yet seen
        if (len(self.compromise_stats) <= id):
            for i in xrange(id+1 - len(self.compromise_stats)):
                stats = {'guard_only_bad':0,\
                            'exit_only_bad':0,\
                            'guard_and_exit_bad':0,\
                            'good':0,\
                            'guard_only_time':None,\
                            'exit_only_time':None,\
                            'guard_and_exit_time':None}
                self.compromise_stats.append(stats)
                
        # update start and end times
        if (self.start_time == None):
            self.start_time = time
        else:
            self.start_time = min(self.start_time, time)
        if (self.end_time == None):
            self.end_time = time
        else:
            self.end_time = max(self.end_time, time)
                
        # increment counts and add times of first compromise
        stats = self.compromise_stats[id]
        guard_bad = guard_ip in self.compromised_relays
        exit_bad = exit_ip in self.compromised_relays
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
            
            
    def output_compromise_rates_plot_data(self, out_dir, out_name):
        """
        Outputs data defining plot of compromise counts as fractions.
        Input:
            out_dir: directory for output files
            out_name: identifying string to be incorporated in filenames
        
        """
        frac_both_bad = []
        frac_exit_bad = []
        frac_guard_bad = []
        line_labels = None

        for stats in self.all_compromise_stats:
            tot_ct = stats['guard_and_exit_bad'] +\
                stats['guard_only_bad'] +\
                stats['exit_only_bad'] + stats['good']
            frac_both_bad.append(\
                float(stats['guard_and_exit_bad']) / float(tot_ct))
            frac_exit_bad.append(\
                float(stats['guard_and_exit_bad'] +\
                    stats['exit_only_bad']) / float(tot_ct))
            frac_guard_bad.append(\
                float(stats['guard_and_exit_bad'] +\
                    stats['guard_only_bad']) / float(tot_ct))
        
        # cdf of both bad
        out_filename = 'analyze-sim.' + out_name +\
            '.exit-guard-comp-rates.pickle' 
        out_pathname = os.path.join(out_dir, out_filename)                           
        with open(out_pathname, 'wb') as f:
            pickle.dump(frac_both_bad, f, pickle.HIGHEST_PROTOCOL)
            pickle.dump(line_labels, f, pickle.HIGHEST_PROTOCOL)
            pickle.dump('Fraction of paths', f, pickle.HIGHEST_PROTOCOL)
            pickle.dump(\
                'Fraction of connections with guard & exit compromised',\
                f, pickle.HIGHEST_PROTOCOL)
            
        # cdf of exit bad
        out_filename = 'analyze-sim.' + out_name +\
            '.exit-comp-rates.pickle'
        out_pathname = os.path.join(out_dir, out_filename)                           
        with open(out_pathname, 'wb') as f:
            pickle.dump(frac_exit_bad, f, pickle.HIGHEST_PROTOCOL)
            pickle.dump(line_labels, f, pickle.HIGHEST_PROTOCOL)
            pickle.dump('Fraction of paths', f, pickle.HIGHEST_PROTOCOL)
            pickle.dump(\
                'Fraction of connections with exit compromised',\
                f, pickle.HIGHEST_PROTOCOL)

        # cdf of guard bad
        out_filename = 'analyze-sim.' + out_name +\
            '.guard-comp-rates.cdf.pdf' 
        out_pathname = os.path.join(out_dir, out_filename)                           
        with open(out_pathname, 'wb') as f:
            pickle.dump(frac_guard_bad, f, pickle.HIGHEST_PROTOCOL)
            pickle.dump(line_labels, f, pickle.HIGHEST_PROTOCOL)
            pickle.dump('Fraction of paths', f, pickle.HIGHEST_PROTOCOL)
            pickle.dump(\
                'Fraction of connections with guard compromised',\
                f, pickle.HIGHEST_PROTOCOL)


    def output_times_to_compromise_plot_data(self, out_dir, out_name):
        """
        Outputs data defining plot of times to first compromise.
        Input: 
            out_dir: output directory
            out_name: string to comprise part of output filenames
        """
        time_len = float(self.end_time - self.start_time)/float(24*60*60)
        line_labels = None     
        guard_times = []
        exit_times = []
        guard_and_exit_times = []        
        for stats in self.all_compromise_stats:
            guard_time = time_len
            exit_time = time_len
            guard_and_exit_time = time_len
            if (stats['guard_only_time'] != None):
                guard_time = float(stats['guard_only_time'] -\
                    self.start_time)/float(24*60*60)
            if (stats['exit_only_time'] != None):
                exit_time = float(stats['exit_only_time'] -\
                    self.start_time)/float(24*60*60)
            if (stats['guard_and_exit_time'] != None):
                ge_time = float(stats['guard_and_exit_time'] -\
                    self.start_time)/float(24*60*60)
                guard_and_exit_time = ge_time
                guard_time = min(guard_time, ge_time)
                exit_time = min(exit_time, ge_time)
            guard_times.append(guard_time)
            exit_times.append(exit_time)
            guard_and_exit_times.append(guard_and_exit_time)
                    
        # cdf for both bad
        out_filename = 'analyze-sim.' + out_name +\
                '.exit-guard-comp-times.pickle'                
        out_pathname = os.path.join(out_dir, out_filename)            
        with open(out_pathname, 'wb') as f:
            pickle.dump(guard_and_exit_times, f,\
                pickle.HIGHEST_PROTOCOL)
            pickle.dump(line_labels, f, pickle.HIGHEST_PROTOCOL)
            pickle.dump('Time to first compromise (days)', f,\
                pickle.HIGHEST_PROTOCOL)
            pickle.dump(\
                'Time to first circuit with guard & exit compromised',\
                f, pickle.HIGHEST_PROTOCOL)

        # cdf for exit bad
        out_filename = 'analyze-sim.' + out_name +\
                '.exit-comp-times.pickle'
        out_pathname = os.path.join(out_dir, out_filename)       
        with open(out_pathname, 'wb') as f:
            pickle.dump(exit_times, f, pickle.HIGHEST_PROTOCOL)
            pickle.dump(line_labels, f, pickle.HIGHEST_PROTOCOL)
            pickle.dump('Time to first compromise (days)', f,\
                pickle.HIGHEST_PROTOCOL)
            pickle.dump('Time to first circuit with exit compromised',\
                f, pickle.HIGHEST_PROTOCOL)
                            
        # cdf for guard bad
        out_filename = 'analyze-sim.' + out_name + '.guard-comp-times.pickle'                
        out_pathname = os.path.join(out_dir, out_filename)        
        with open(out_pathname, 'wb') as f:
            pickle.dump(guard_times, f, pickle.HIGHEST_PROTOCOL)
            pickle.dump(line_labels, f, pickle.HIGHEST_PROTOCOL)
            pickle.dump('Time to first compromise (days)', f,\
                pickle.HIGHEST_PROTOCOL)
            pickle.dump('Time to first circuit with guard compromised',\
                f, pickle.HIGHEST_PROTOCOL)
                
                
    def output_stats_plot_data(self, out_dir, out_name):
        """Output data defining cdf some of the statistics collected."""
        self.output_compromise_rates_plot_data(out_dir, out_name)
        self.output_times_to_compromise_plot_data(out_dir, out_name)            
    

class CompromiseTopRelays:
    """
    Keeps statistics on circuit end compromises, considering ranges for
    the number of top guard and top exits compromised.
    """
    def __init__(self, top_guards, top_exits):
        self.top_guards = top_guards
        self.top_exits = top_exits
        self.all_compromise_stats = []
        self.start_time = None
        self.end_time = None
        
        
    def start(self):
        """Data from new log file will be processed."""
        self.compromise_stats = []
        
        
    def end(self):
        """Store in final form stats collected from a log file."""
        self.all_compromise_stats.extend(self.compromise_stats)


    def log_line(self, id, time, guard_ip, exit_ip):
        """Adds statistics based on fields from log line."""
        # add entries for sample not yet seen
        if (len(self.compromise_stats) <= id):
            for i in xrange(id+1 - len(self.compromise_stats)):
                # construct matrix storing counts for possible # comp relays
                stats = []
                for j in xrange(len(self.top_guards)+1):
                    stats.append([])
                    for k in xrange(len(self.top_exits)+1):
                        stats[j].append({'guard_only_bad':0,\
                                        'exit_only_bad':0,\
                                        'guard_and_exit_bad':0,\
                                        'good':0,\
                                        'guard_only_time':None,\
                                        'exit_only_time':None,\
                                        'guard_and_exit_time':None})
                self.compromise_stats.append(stats)
                
        # update start and end times
        if (self.start_time == None):
            self.start_time = time
        else:
            self.start_time = min(self.start_time, time)
        if (self.end_time == None):
            self.end_time = time
        else:
            self.end_time = max(self.end_time, time)

        # find first occurrence of guard_ip and exit_ip in top_guards and
        # top_exits - .index() would raise error if not present
        top_guards_guard_idx = None
        top_guards_exit_idx = None
        top_exits_guard_idx = None
        top_exits_exit_idx = None
        for i, top_guard in enumerate(self.top_guards):
            if (guard_ip == top_guard):
                top_guards_guard_idx = i+1
                break
        for i, top_guard in enumerate(self.top_guards):
            if (exit_ip == top_guard):
                top_guards_exit_idx = i+1
                break                
        for i, top_exit in enumerate(self.top_exits):
            if (guard_ip == top_exit):
                top_exits_guard_idx = i+1
                break
        for i, top_exit in enumerate(self.top_exits):
            if (exit_ip == top_exit):
                top_exits_exit_idx = i+1
                break    
                
        # increment counts and add times of first compromise
        for i in xrange(len(self.compromise_stats[id])):
            for j in xrange(len(self.compromise_stats[id][i])):
                stats = self.compromise_stats[id][i][j]
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
              
                        
    def write_stats(self, out_dir, out_name):
        """Write stats to out_dir in files with names containing
        out_name."""        
        # only write stats for powers of two adversaries
        num_guards = 0
        while (num_guards <= len(self.top_guards)):
            if (num_guards == 0):
                num_exits = 1
            else:
                num_exits = 0
            while (num_exits <= len(self.top_exits)):
                out_filename = 'analyze-sim.' + out_name + '.' +\
                    str(num_guards) + '-' + str(num_exits) + '.out'
                with open(os.path.join(out_dir, out_filename), 'w') as f:
                    f.write('#\tbad guard&exit\tbad guard only\tbad exit only\tgood\tguard&exit time\tguard only time\texit only time\n')
                    for i, comp_stats in enumerate(self.all_compromise_stats):
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
                
                
    def output_compromise_rates_plot_data(self, out_dir, out_name):
        """
        Outputs data defining plot of compromise counts as fractions.
        Input:
            out_dir: directory for output files
            out_name: identifying string to be incorporated in filenames
        
        """
        # only output for powers of two adversaries
        num_guards = 0
        while (num_guards <= len(self.top_guards)):
            if (num_guards == 0):
                num_exits = 1
            else:
                num_exits = 0
            num_exit_frac_both_bad = []
            num_exit_frac_exit_bad = []
            num_exit_frac_guard_bad = []
            line_labels = []
            while (num_exits <= len(self.top_exits)):
                # fraction of connection with bad guard and exit
                frac_both_bad = []
                frac_exit_bad = []
                frac_guard_bad = []
                for stats in self.all_compromise_stats:
                    adv_stats = stats[num_guards][num_exits]
                    tot_ct = adv_stats['guard_and_exit_bad'] +\
                        adv_stats['guard_only_bad'] +\
                        adv_stats['exit_only_bad'] + adv_stats['good']
                    frac_both_bad.append(\
                        float(adv_stats['guard_and_exit_bad']) / float(tot_ct))
                    frac_exit_bad.append(\
                        float(adv_stats['guard_and_exit_bad'] +\
                            adv_stats['exit_only_bad']) / float(tot_ct))
                    frac_guard_bad.append(\
                        float(adv_stats['guard_and_exit_bad'] +\
                            adv_stats['guard_only_bad']) / float(tot_ct))
                num_exit_frac_both_bad.append(frac_both_bad)
                num_exit_frac_exit_bad.append(frac_exit_bad)
                num_exit_frac_guard_bad.append(frac_guard_bad)
                line_labels.append('{0} comp. exits'.format(num_exits))
                if (num_exits == 0):
                    num_exits = 1
                else:
                    num_exits *= 2
            
            # cdf of both bad
            out_filename = 'analyze-sim.' + out_name + '.' +\
                str(num_guards) + '-guards.exit-guard-comp-rates.pickle' 
            out_pathname = os.path.join(out_dir, out_filename)                           
            with open(out_pathname, 'wb') as f:
                pickle.dump(num_exit_frac_both_bad, f, pickle.HIGHEST_PROTOCOL)
                pickle.dump(line_labels, f, pickle.HIGHEST_PROTOCOL)
                pickle.dump('Fraction of paths', f, pickle.HIGHEST_PROTOCOL)
                pickle.dump(\
                    'Fraction of connections with guard & exit compromised',\
                    f, pickle.HIGHEST_PROTOCOL)

                
            # cdf of exit bad
            out_filename = 'analyze-sim.' + out_name + '.' +\
                str(num_guards) + '.-guards.exit-comp-rates.pickle'
            out_pathname = os.path.join(out_dir, out_filename)                           
            with open(out_pathname, 'wb') as f:
                pickle.dump(num_exit_frac_exit_bad, f, pickle.HIGHEST_PROTOCOL)
                pickle.dump(line_labels, f, pickle.HIGHEST_PROTOCOL)
                pickle.dump('Fraction of paths', f, pickle.HIGHEST_PROTOCOL)
                pickle.dump(\
                    'Fraction of connections with exit compromised',\
                    f, pickle.HIGHEST_PROTOCOL)

            # cdf of guard bad
            out_filename = 'analyze-sim.' + out_name + '.' +\
                str(num_guards) + '.-guards.guard-comp-rates.cdf.pdf' 
            out_pathname = os.path.join(out_dir, out_filename)                           
            with open(out_pathname, 'wb') as f:
                pickle.dump(num_exit_frac_guard_bad, f,\
                    pickle.HIGHEST_PROTOCOL)
                pickle.dump(line_labels, f, pickle.HIGHEST_PROTOCOL)
                pickle.dump('Fraction of paths', f, pickle.HIGHEST_PROTOCOL)
                pickle.dump(\
                    'Fraction of connections with guard compromised',\
                    f, pickle.HIGHEST_PROTOCOL)

            if (num_guards == 0):
                num_guards = 1
            else:
                num_guards *= 2


    def output_times_to_compromise_plot_data(self, out_dir, out_name):
        """
        Outputs data defining plot of times to first compromise.
        Input: 
            out_dir: output directory
            out_name: string to comprise part of output filenames
        """
        time_len = float(self.end_time - self.start_time)/float(24*60*60)
        # only plot for powers of two adversaries
        num_guards = 0
        while (num_guards <= len(self.top_guards)):
            if (num_guards == 0):
                num_exits = 1
            else:
                num_exits = 0
            num_exit_guard_times = []
            num_exit_exit_times = []
            num_exit_guard_and_exit_times = []
            line_labels = []          
            while (num_exits <= len(self.top_exits)):
                guard_times = []
                exit_times = []
                guard_and_exit_times = []
                for stats in self.all_compromise_stats:
                    adv_stats = stats[num_guards][num_exits]
                    guard_time = time_len
                    exit_time = time_len
                    guard_and_exit_time = time_len
                    if (adv_stats['guard_only_time'] != None):
                        guard_time = float(adv_stats['guard_only_time'] -\
                            self.start_time)/float(24*60*60)
                    if (adv_stats['exit_only_time'] != None):
                        exit_time = float(adv_stats['exit_only_time'] -\
                            self.start_time)/float(24*60*60)
                    if (adv_stats['guard_and_exit_time'] != None):
                        ge_time = float(adv_stats['guard_and_exit_time'] -\
                            self.start_time)/float(24*60*60)
                        guard_and_exit_time = ge_time
                        guard_time = min(guard_time, ge_time)
                        exit_time = min(exit_time, ge_time)
                    guard_times.append(guard_time)
                    exit_times.append(exit_time)
                    guard_and_exit_times.append(guard_and_exit_time)
                num_exit_guard_times.append(guard_times)
                num_exit_exit_times.append(exit_times)
                num_exit_guard_and_exit_times.append(guard_and_exit_times)
                line_labels.append('{0} comp. exits'.format(num_exits))
                if (num_exits == 0):
                    num_exits = 1
                else:
                    num_exits *= 2
                    
            # cdf for both bad
            out_filename = 'analyze-sim.' + out_name + '.' +\
                    str(num_guards) + '-guards.exit-guard-comp-times.pickle'                
            out_pathname = os.path.join(out_dir, out_filename)            
            with open(out_pathname, 'wb') as f:
                pickle.dump(num_exit_guard_and_exit_times, f,\
                    pickle.HIGHEST_PROTOCOL)
                pickle.dump(line_labels, f, pickle.HIGHEST_PROTOCOL)
                pickle.dump('Time to first compromise (days)', f,\
                    pickle.HIGHEST_PROTOCOL)
                pickle.dump(\
                    'Time to first circuit with guard & exit compromised',\
                    f, pickle.HIGHEST_PROTOCOL)

            # cdf for exit bad
            out_filename = 'analyze-sim.' + out_name + '.' +\
                    str(num_guards) + '-guards.exit-comp-times.pickle'
            out_pathname = os.path.join(out_dir, out_filename)       
            with open(out_pathname, 'wb') as f:
                pickle.dump(num_exit_exit_times, f,\
                    pickle.HIGHEST_PROTOCOL)
                pickle.dump(line_labels, f, pickle.HIGHEST_PROTOCOL)
                pickle.dump('Time to first compromise (days)', f,\
                    pickle.HIGHEST_PROTOCOL)
                pickle.dump(\
                    'Time to first circuit with exit compromised',\
                    f, pickle.HIGHEST_PROTOCOL)
                                
            # cdf for guard bad
            out_filename = 'analyze-sim.' + out_name + '.' +\
                    str(num_guards) + '-guards.guard-comp-times.pickle'                
            out_pathname = os.path.join(out_dir, out_filename)        
            with open(out_pathname, 'wb') as f:
                pickle.dump(num_exit_guard_times, f,\
                    pickle.HIGHEST_PROTOCOL)
                pickle.dump(line_labels, f, pickle.HIGHEST_PROTOCOL)
                pickle.dump('Time to first compromise (days)', f,\
                    pickle.HIGHEST_PROTOCOL)
                pickle.dump(\
                    'Time to first circuit with guard compromised',\
                    f, pickle.HIGHEST_PROTOCOL)
                               
            if (num_guards == 0):
                num_guards = 1
            else:
                num_guards *= 2
                
                
    def output_stats_plot_data(self, out_dir, out_name):
        """Output data defining cdf some of the statistics collected."""
        self.output_compromise_rates_plot_data(out_dir, out_name)
        self.output_times_to_compromise_plot_data(out_dir, out_name)
        
        
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
    print('#\tProb.\tUptime\tFingerprint\t\t\t\t\t\t\tNickname')
    for fp, guard in initial_guards_items:
        if (cum_prob >= guard_cum_prob):
            break
        print('{0}\t{1:.4f}\t{2}\t{3}\t{4}'.format(i, guard['prob'], \
            guard['uptime'], fp, guard['rel_stat'].nickname))
        cum_prob += guard['prob']
        i += 1

    # print out top exits by total probability-weighted uptime
    exits_tot_bw_sorted = exits_tot_bw.items()
    exits_tot_bw_sorted.sort(key = lambda x: x[1]['tot_bw'], reverse=True)
    i = 1
    print('Top {0} exits to {1}:{2} by probability-weighted uptime'.\
        format(num_exits, ip, port))
    print('#\ttot_bw\tmax_pr\tmin_pr\tFingerprint\t\t\t\t\t\t\tNickname')
    for fprint, bw_dict in exits_tot_bw_sorted[0:num_exits]:
        print('{0}\t{1:.4f}\t{2:.4f}\t{3:.4f}\t{4}\t{5}'.\
            format(i, bw_dict['tot_bw'], bw_dict['max_prob'],\
                bw_dict['min_prob'], fprint, bw_dict['nickname']))
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

        
def simulation_analysis(log_files, adv):
    """Runs log file fields through given adversary object."""
    for log_file in log_files:        
        with open(log_file, 'r') as lf:
            print('Processing file {0}.'.format(os.path.basename(log_file)))

            # prepare for new log file
            adv.start()

            lf.readline() # read header line
            i = 0
            for line in lf:
                if (i % 100000 == 0):
                    print('Read {0} lines.'.format(i))
                i = i+1
                line = line[0:-1] # cut off final newline
                line_fields = line.split('\t')
                id = int(line_fields[0])
                time = int(line_fields[1])
                guard_ip = line_fields[2]
                exit_ip = line_fields[4]
                adv.log_line(id, time, guard_ip, exit_ip)
                
            # finalize stats    
            adv.end()

if __name__ == '__main__':
    usage = 'Usage: pathsim_analysis.py [command]\nCommands:\n\
\tnetwork [in_dir]:  Analyze the network status files in in_dir.\n\
\tsimulation [in_dir] [out_dir] [out_name]: Analyze the simulation logs in in_dir against adversary and write statistics to files in out_dir in files with names containing [out_name].'
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
            
    elif (command == 'simulation'):
        if (len(sys.argv) < 5):
            print(usage)
            sys.exit(1)
            
        # get list of log files
        in_dir = sys.argv[2]
        out_dir = sys.argv[3]
        out_name = sys.argv[4]
        log_files = []
        for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
            for filename in filenames:
                if (filename[0] != '.'):
                    log_files.append(os.path.join(dirpath,filename))
        log_files.sort(key = lambda x: os.path.basename(x))
        
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

        top_relay_adversary = CompromiseTopRelays(top_guard_ips, top_exit_ips)        
        simulation_analysis(log_files, top_relay_adversary)
        #top_relay_adversary.write_stats(out_dir, out_name)
        top_relay_adversary.output_stats_plot_data(out_dir, out_name)
        
        
        # taken from fingerprints_to_ips.py
        pprivcom_ips = ['192.162.102.50', '212.117.161.80', '204.45.70.98',\
            '95.128.242.224', '84.19.178.6', '95.143.192.159',\
            '92.243.26.232', '212.117.177.110', '50.7.240.10',\
            '41.215.241.234', '195.254.134.10', '208.53.158.59',\
            '82.195.232.218', '192.162.100.209', '95.211.13.145',\
            '213.163.64.43', '95.211.10.25', '46.37.167.122',\
            '212.117.162.222', '46.37.168.82', '67.205.112.74',\
            '84.19.178.7', '95.211.99.91', '79.134.255.67',\
            '213.163.65.50', '195.254.134.194', '212.117.160.22',\
            '212.117.162.192', '212.117.163.21', '46.165.196.73',\
            '212.117.165.197', '212.117.162.194']
        chaoscomputerclub_ips = ['192.162.102.224', '80.237.226.75',\
            '62.113.219.5', '62.113.219.6', '31.172.30.1', '80.237.226.74',\
            '62.113.219.4', '31.172.30.2', '31.172.30.3', '62.113.219.3',\
            '31.172.30.4', '80.237.226.76', '80.237.226.73']

        compromised_relays = []
        compromised_relays.extend(pprivcom_ips)
        compromised_relays.extend(chaoscomputerclub_ips)
        compromised_groups_adversary = CompromisedSet(compromised_relays)
        simulation_analysis(log_files, compromised_groups_adversary)
        # include string identifying malicious groups in outname
        compromised_groups_adversary.output_stats_plot_data(out_dir, out_name)