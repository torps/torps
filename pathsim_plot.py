import sys
import numpy
import matplotlib
#matplotlib.use('PDF')
import matplotlib.pyplot
import matplotlib.mlab
import math


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

def plot_compromise_rates(comp_cts, fname):
    """
    Plots a histogram of compromise counts as fractions.
    Input: comp_cts: array of dicts with keys
        'guard_and_exit_bad', 'guard_only_bad', 'exit_only_bad', and 'good'.
    """
    # fraction of connection with bad guard and exit
    frac_both_bad = []
    for cc in comp_cts:
        tot_ct = cc['guard_and_exit_bad']+cc['guard_only_bad']+\
            cc['exit_only_bad']+cc['good']
        frac_both_bad.append(\
            float(cc['guard_and_exit_bad']) / float(tot_ct))

    fig = matplotlib.pyplot.figure()
    
    # histogram
    #ax = fig.add_subplot(111)
    #ax.hist(frac_both_bad, bins=30)
    #ax.set_xlabel('Fraction of compromised paths')
    #ax.set_ylabel('Number of samples')
    ##matplotlib.pyplot.hist(frac_both_bad)    
    
    # cdf
    x, y = getcdf(frac_both_bad)
    matplotlib.pyplot.figure()
    matplotlib.pyplot.plot(x, y, color='b')
    matplotlib.pyplot.xlim(xmin=0.0)
    matplotlib.pyplot.ylim(ymin=0.0)
    matplotlib.pyplot.xlabel('Fraction of compromised paths')
    matplotlib.pyplot.ylabel("Cumulative probability")
    matplotlib.pyplot.grid()

    # output    
    #matplotlib.pyplot.show()
    matplotlib.pyplot.savefig(fname)
    
def plot_time_to_compromise(comp_times, period_start, period_end, fname):
    """
    Plots a histogram of times to first compromise.
    Input: comp_times: list of lists, each contains comp timestamp or None
        period_start: timestamp of when simulation period started
        period_end: timestamp of when simulation period ended
        fname: filename to write to
    """
    time_len = float(period_end - period_start)/float(24*60*60)
    time_to_comp = []
    for t in comp_times:
        if (t != None):
            time_to_comp.append(float(t - period_start)/float(24*60*60))
        else:
            time_to_comp.append(time_len)
    fig = matplotlib.pyplot.figure()
    
    # histogram
    #ax = fig.add_subplot(111)
    #ax.hist(time_to_comp, bins=30)
    #ax.set_xlabel('Time to first compromise (days)')
    #ax.set_ylabel('Number of samples')
    ##matplotlib.pyplot.hist(frac_both_bad)

    # cdf
    x, y = getcdf(time_to_comp)
    matplotlib.pyplot.figure()
    matplotlib.pyplot.plot(x, y, color='b')
    matplotlib.pyplot.xlim(xmin=0.0)
    matplotlib.pyplot.ylim(ymin=0.0)
    matplotlib.pyplot.xlabel('Time to first compromise (days)')
    matplotlib.pyplot.ylabel("Cumulative probability")
    matplotlib.pyplot.xticks(numpy.arange(0, math.ceil(time_len)+1, 5))
    matplotlib.pyplot.yticks(numpy.arange(0, 1.05, .05))
    matplotlib.pyplot.grid()

    # output    
    #matplotlib.pyplot.show()
    matplotlib.pyplot.savefig(fname)


if __name__ == '__main__':
    """Plot histograms of the times to first compromise \
    and the compromise fractions for experiment with a starting\
    timestamp of [start] and an ending timestamp of [end]."""
    usage = 'Usage: pathsim_plot.py [in_dir] [start] [end]'
    if (len(sys.argv) < 4):
        print(usage)
        sys.exit(1)

    in_dir = sys.argv[1]
# timestamps for current experiment
# 3/2/2012: 1330646400
# 4/30/2012: 1335829800    
    period_start = int(sys.argv[2])
    period_end = int(sys.argv[3])
    
    stats_files = []
    for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
        for filename in filenames:
            if (filename[0] != '.'):
                stats_files.append(os.path.join(dirpath,filename))    

# '#\tbad guard&exit\tbad guard only\tbad exit only\tgood\tguard&exit time\tguard only time\texit only time\n'
    for stats_file in stats_files:
        guard_exit_times = []
        guard_times = []
        exit_times = []
        comp_cts = []
        with open(stats_file) as f:
            print('Plotting from file {0}'.format(stats_file))
            f.readline() # read in header file
            for line in f:
                line_split = line[:-1].split('\t') # omit final newline
                comp_cts.append({\
                   'guard_and_exit_bad':int(line_split[1]),\
                   'guard_only_bad':int(line_split[2]),\
                   'exit_only_bad':int(line_split[3]),\
                   'good':int(line_split[4])})          
                guard_exit_time = int(line_split[5])
                guard_time = int(line_split[6])
                exit_time = int(line_split[7])
                guard_exit_times.append(guard_exit_time \
                    if guard_exit_time != -1 else None)
                guard_times.append(guard_time \
                    if guard_time != -1 else None)
                exit_times.append(exit_time \
                    if exit_time != -1 else None)
        plot_time_to_compromise([guard_exit_times,guard_times,exit_times],\
            period_start, period_end, in_file + '.comp-times.cdf.pdf')        
        plot_compromise_rates(comp_cts, in_file + '.comp-rates.cdf.pdf')