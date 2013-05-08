# Isolate code that uses numpy and matplotlib here
# so pypy can be used with the rest.
import os
import cPickle as pickle
import sys
import numpy
import matplotlib
matplotlib.use('PDF') # alerts matplotlib that display not required
import matplotlib.pyplot
#import matplotlib.mlab
import math


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

def plot_cdf(lines, line_labels, xlabel, title, location, out_pathname,
    figsize = None, fontsize = 'small'):
    """Saves cdf for given lines in out_name."""
    fig = matplotlib.pyplot.figure(figsize = figsize)
    line_styles = ['-v', '-o', '-s', '-*', '-x', '-D', '-+']
    num_markers = 10

    # histogram
    #ax = fig.add_subplot(111)
    #ax.hist(lines, bins=30)
    #ax.set_xlabel('Fraction of compromised paths')
    #ax.set_ylabel('Number of samples')
    ##matplotlib.pyplot.hist(lines)    
    
    if (line_labels != None):
        i = 0
        for data_points, line_label in zip(lines, line_labels):
            # cut off points with largest value
            data_max = max(data_points)
            data_shown = filter(lambda x: x < data_max, data_points)
            shown_percentile = float(len(data_shown)) / len(data_points)
            x, y = getcdf(data_points, shown_percentile)
            matplotlib.pyplot.plot(x, y, line_styles[i % len(line_styles)],
                label = line_label,
                linewidth = 2,
                markevery = int(math.floor(len(x)/num_markers)))
            i += 1
        matplotlib.pyplot.legend(loc=location, fontsize = fontsize)
    else:
        x, y = getcdf(lines)
        matplotlib.pyplot.plot(x, y)
    matplotlib.pyplot.xlim(xmin=0.0)
    matplotlib.pyplot.ylim(ymin=0.0)
    matplotlib.pyplot.yticks(numpy.arange(0, 1.1, 0.1))
    matplotlib.pyplot.xlabel(xlabel, fontsize=fontsize)
    matplotlib.pyplot.ylabel('Cumulative probability', fontsize=fontsize)
#    matplotlib.pyplot.title(title, fontsize=fontsize)
    matplotlib.pyplot.grid()
    matplotlib.pyplot.tight_layout()
    
    # output    
    #matplotlib.pyplot.show()
    matplotlib.pyplot.savefig(out_pathname)
##########

def compromised_set_plot_rates(compromise_stats, line_labels, out_dir,
    out_name, figsize = None, fontsize = 'small'):
    """
    Plots cdfs of compromise fractions for compromised-set statistics.
    Input:
        compromise_stats: (list) each element is a list of statistics
            calculated for the compromised set
        line_labels: (list) each element is a line label or None if only
            one line to be plotted
        out_dir: directory for output files
        out_name: identifying string to be incorporated in filenames
    
    """
    stats_frac_both_bad = []
    stats_frac_exit_bad = []
    stats_frac_guard_bad = []

    for stats_list in compromise_stats:
        frac_both_bad = []
        frac_exit_bad = []
        frac_guard_bad = []
        for stats in stats_list:
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
        stats_frac_both_bad.append(frac_both_bad)
        stats_frac_exit_bad.append(frac_exit_bad)
        stats_frac_guard_bad.append(frac_guard_bad)
        
    # flatten stats list when just one line
    if (line_labels == None):
        stats_frac_both_bad = stats_frac_both_bad[0]
        stats_frac_exit_bad = stats_frac_exit_bad[0]
        stats_frac_guard_bad = stats_frac_guard_bad[0]
    
    # cdf of both bad
    out_filename = out_name + '.exit-guard-comp-rates.cdf.pdf' 
    out_pathname = os.path.join(out_dir, out_filename)
    plot_cdf(stats_frac_both_bad, line_labels, 'Fraction of streams',
        '', 'lower right', out_pathname, figsize, fontsize)

    # cdf of exit bad
    out_filename = out_name + '.exit-comp-rates.cdf.pdf'
    out_pathname = os.path.join(out_dir, out_filename)                           
    plot_cdf(stats_frac_exit_bad, line_labels, 'Fraction of streams',
        '', 'lower right', out_pathname, figsize, fontsize)

    # cdf of guard bad
    out_filename = out_name + '.guard-comp-rates.cdf.pdf' 
    out_pathname = os.path.join(out_dir, out_filename)                           
    plot_cdf(stats_frac_guard_bad, line_labels, 'Fraction of streams',
        '', 'lower right', out_pathname, figsize, fontsize)


def compromised_set_plot_times(start_times, end_times, compromise_stats,
    line_labels, out_dir, out_name, figsize = None, fontsize = 'small'):
    """
    Plots cdfs of times to compromise for compromised-set statistics.
    Input: 
        start_times: timestamps of simulation starts for each dataset
        end_times: timestamps of simulation ends for each dataset
        compromise_stats: (list) each element is a list of statistics
            calculated for compromised set
        out_dir: output directory
        out_name: string to comprise part of output filenames
    """
    stats_guard_times = []
    stats_exit_times = []
    stats_guard_and_exit_times = []
    for start_time, end_time, stats_list in zip(start_times, end_times,
        compromise_stats):
        time_len = float(end_time - start_time)/float(24*60*60)
        guard_times = []
        exit_times = []
        guard_and_exit_times = []        
        for stats in stats_list:
            guard_time = time_len
            exit_time = time_len
            guard_and_exit_time = time_len
            if (stats['guard_only_time'] != None):
                guard_time = float(stats['guard_only_time'] -\
                    start_time)/float(24*60*60)
            if (stats['exit_only_time'] != None):
                exit_time = float(stats['exit_only_time'] -\
                    start_time)/float(24*60*60)
            if (stats['guard_and_exit_time'] != None):
                ge_time = float(stats['guard_and_exit_time'] -\
                    start_time)/float(24*60*60)
                guard_and_exit_time = ge_time
                guard_time = min(guard_time, ge_time)
                exit_time = min(exit_time, ge_time)
            guard_times.append(guard_time)
            exit_times.append(exit_time)
            guard_and_exit_times.append(guard_and_exit_time)
        stats_guard_times.append(guard_times)
        stats_exit_times.append(exit_times)
        stats_guard_and_exit_times.append(guard_and_exit_times)
        
    # flatten stats when just one line
    if (line_labels == None):
        stats_guard_times = stats_guard_times[0]
        stats_exit_times = stats_exit_times[0]
        stats_guard_and_exit_times = stats_guard_and_exit_times[0]
                
    # cdf for both bad
    out_filename = out_name + '.exit-guard-comp-times.cdf.pdf'                
    out_pathname = os.path.join(out_dir, out_filename)
    plot_cdf(stats_guard_and_exit_times, line_labels,
        'Days from first stream',
        '', 'lower right', out_pathname, figsize, fontsize)

    # cdf for exit bad
    out_filename = out_name + '.exit-comp-times.cdf.pdf'
    out_pathname = os.path.join(out_dir, out_filename)       
    plot_cdf(stats_exit_times, line_labels,
        'Days from first stream',
        '', 'lower right', out_pathname, figsize, fontsize)
                        
    # cdf for guard bad
    out_filename = out_name + '.guard-comp-times.cdf.pdf'
    out_pathname = os.path.join(out_dir, out_filename)        
    plot_cdf(stats_guard_times, line_labels,
        'Days from first stream',
        '', 'lower right', out_pathname, figsize, fontsize)

                
def compromised_set_plot(pathnames_list, line_labels, out_dir, out_name,
    figsize = None, fontsize = 'small'):
    """Plots cdfs for compromised-set statistics."""
    if (line_labels == None): # assume pathnames given as flat list
        pathnames_list = [pathnames_list]
    # aggregate the stats  
    start_times = [None]*len(pathnames_list)
    end_times = [None]*len(pathnames_list)
    compromise_stats = []
    for i in xrange(len(pathnames_list)):
        compromise_stats.append([])
    for i, pathnames in enumerate(pathnames_list):
        for pathname in pathnames:
            with open(pathname) as f:
                if (out_name == None):
                    filename = os.path.basename(pathname)
                    filename_split = filename.split('.')
                    out_name = '.'.join(filename_split[:-2])
                new_start_time = pickle.load(f)
                new_end_time = pickle.load(f)
                new_compromise_stats = pickle.load(f)
                if (start_times[i] == None):
                    start_times[i] = new_start_time
                else:
                    start_times[i] = min(start_times[i], new_start_time)
    
                if (end_times[i] == None):
                    end_times[i] = new_end_time
                else:
                    end_times[i] = min(end_times[i], new_end_time)
                compromise_stats[i].extend(new_compromise_stats)
    
    compromised_set_plot_rates(compromise_stats, line_labels, out_dir,
        out_name, figsize, fontsize)

    compromised_set_plot_times(start_times, end_times, compromise_stats,
        line_labels, out_dir, out_name, figsize, fontsize)
        
                   
def compromised_top_relays_plot_rates(compromise_stats, out_dir, out_name):
    """
    Plots cdfs of compromise fractions for stats on compromised top relays.
    Input:
        compromise_stats: Statistics calculated for compromised top relays
        out_dir: directory for output files
        out_name: identifying string to be incorporated in filenames
    
    """
    
    if (len(compromise_stats) == 0):
        raise ValueError('compromise_stats input cannot be empty')
    if (len(compromise_stats[0]) == 0):
        raise ValueError('Need statistics for each top guard/exit pair.')
    num_top_guards = len(compromise_stats[0])
    num_top_exits = len(compromise_stats[0][0])
    # only output for powers of two adversaries
    num_guards = 0
    while (num_guards <= num_top_guards):
        if (num_guards == 0):
            num_exits = 1
        else:
            num_exits = 0
        num_exit_frac_both_bad = []
        num_exit_frac_exit_bad = []
        num_exit_frac_guard_bad = []
        line_labels = []
        while (num_exits <= num_top_exits):
            # fraction of connection with bad guard and exit
            frac_both_bad = []
            frac_exit_bad = []
            frac_guard_bad = []
            for stats in compromise_stats:
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
        out_filename = out_name + '.' +\
            str(num_guards) + '-guards.exit-guard-comp-rates.cdf.pdf'
        out_pathname = os.path.join(out_dir, out_filename)                           
        plot_cdf(num_exit_frac_both_bad, line_labels, 'Fraction of paths',\
            'Fraction of connections with guard & exit compromised',\
            'lower right', out_pathname)  
            
        # cdf of exit bad
        out_filename = out_name + '.' +\
            str(num_guards) + '-guards.exit-comp-rates.cdf.pdf'
        out_pathname = os.path.join(out_dir, out_filename)                           
        plot_cdf(num_exit_frac_exit_bad, line_labels, 'Fraction of paths',\
            'Fraction of connections with exit compromised',\
            'lower right', out_pathname)

        # cdf of guard bad
        out_filename = out_name + '.' +\
            str(num_guards) + '-guards.guard-comp-rates.cdf.pdf' 
        out_pathname = os.path.join(out_dir, out_filename)                           
        plot_cdf(num_exit_frac_guard_bad, line_labels, 'Fraction of paths',\
            'Fraction of connections with guard compromised',\
            'lower right', out_pathname)

        if (num_guards == 0):
            num_guards = 1
        else:
            num_guards *= 2


def compromised_top_relays_plot_times(start_time, end_time, compromise_stats,\
    out_dir, out_name):
    """
    Plots cdfs of times to compromise for statistics on compromised top relays.
    Input: 
        start_time: timestamp of simulation start
        end_time: timestamp of simulation end
        compromise_stats: Statistics calculated for compromised top relays
        out_dir: output directory
        out_name: string to comprise part of output filenames
    """
    time_len = float(end_time - start_time)/float(24*60*60)

    if (len(compromise_stats) == 0):
        raise ValueError('compromise_stats input cannot be empty')
    if (len(compromise_stats[0]) == 0):
        raise ValueError('Need statistics for each top guard/exit pair.')
    num_top_guards = len(compromise_stats[0])
    num_top_exits = len(compromise_stats[0][0])
    # only output for powers of two adversaries
    num_guards = 0
    while (num_guards <= num_top_guards):
        if (num_guards == 0):
            num_exits = 1
        else:
            num_exits = 0
        num_exit_guard_times = []
        num_exit_exit_times = []
        num_exit_guard_and_exit_times = []
        line_labels = []          
        while (num_exits <= num_top_exits):
            guard_times = []
            exit_times = []
            guard_and_exit_times = []
            for stats in compromise_stats:
                adv_stats = stats[num_guards][num_exits]
                guard_time = time_len
                exit_time = time_len
                guard_and_exit_time = time_len
                if (adv_stats['guard_only_time'] != None):
                    guard_time = float(adv_stats['guard_only_time'] -\
                        start_time)/float(24*60*60)
                if (adv_stats['exit_only_time'] != None):
                    exit_time = float(adv_stats['exit_only_time'] -\
                        start_time)/float(24*60*60)
                if (adv_stats['guard_and_exit_time'] != None):
                    ge_time = float(adv_stats['guard_and_exit_time'] -\
                        start_time)/float(24*60*60)
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
        out_filename = out_name + '.' +\
                str(num_guards) + '-guards.exit-guard-comp-times.cdf.pdf'                
        out_pathname = os.path.join(out_dir, out_filename)     
        plot_cdf(num_exit_guard_and_exit_times, line_labels,\
            'Time to first compromise (days)',\
            'Time to first circuit with guard & exit compromised',\
            'upper left', out_pathname)

        # cdf for exit bad
        out_filename = out_name + '.' +\
                str(num_guards) + '-guards.exit-comp-times.cdf.pdf'
        out_pathname = os.path.join(out_dir, out_filename) 
        plot_cdf(num_exit_exit_times, line_labels,\
            'Time to first compromise (days)',\
            'Time to first circuit with exit compromised',\
            'upper left', out_pathname)

        # cdf for guard bad
        out_filename = out_name + '.' +\
                str(num_guards) + '-guards.guard-comp-times.cdf.pdf'
        out_pathname = os.path.join(out_dir, out_filename)  
        plot_cdf(num_exit_guard_times, line_labels,\
            'Time to first compromise (days)',\
            'Time to first circuit with guard compromised',\
            'upper left', out_pathname)
                           
        if (num_guards == 0):
            num_guards = 1
        else:
            num_guards *= 2
                
       
def compromised_top_relays_plot(pathnames, out_dir):
    """Plots cdfs for statistics on compromised top relays"""    
    # aggregate the stats        
    start_time = None
    end_time = None
    compromise_stats = []
    out_name = None
    for pathname in pathnames:
        with open(pathname) as f:
            if (out_name == None):
                filename = os.path.basename(pathname)
                filename_split = filename.split('.')
                out_name = '.'.join(filename_split[:-2])
            new_start_time = pickle.load(f)
            new_end_time = pickle.load(f)
            new_compromise_stats = pickle.load(f)
            if (start_time == None):
                start_time = new_start_time
            else:
                start_time = min(start_time, new_start_time)
            if (end_time == None):
                end_time = new_end_time
            else:
                end_time = min(end_time, new_end_time)
            compromise_stats.extend(new_compromise_stats)

    compromised_top_relays_plot_rates(compromise_stats, out_dir, out_name)
    compromised_top_relays_plot_times(start_time, end_time, compromise_stats,\
        out_dir, out_name)
        

if __name__ == '__main__':
    usage = 'Usage: pathsim_plot.py [plot type] [in_dir] [out_dir]: \nTakes all files in in_dir, plots their contents according to type, and outputs the results to out_dir. Plot type is one of "set" or "top".'
    if (len(sys.argv) < 4):
        print(usage)
        sys.exit(1)
        
    plot_type = sys.argv[1]
    if (plot_type != 'set') and (plot_type != 'top'):
        print(usage)
        sys.exit(1)
    in_dir = sys.argv[2]
    out_dir = sys.argv[3]
    
    pathnames = []
    for dirpath, dirnames, fnames in os.walk(in_dir):
        for fname in fnames:
            pathnames.append(os.path.join(dirpath,fname))
    pathnames.sort()
    
    if (plot_type == 'set'):
        # plot data from compromised-set adversary
        compromised_set_plot(pathnames, None, out_dir, None)
    elif (plot_type == 'top'):
        compromised_top_relays_plot(pathnames, out_dir)