import sys
import numpy
import matplotlib.pyplot
import matplotlib.mlab

def plot_compromise_rates(comp_cts):
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
    ax = fig.add_subplot(111)
    ax.hist(frac_both_bad, bins=50)
    ax.set_xlabel('Fraction of compromised paths')
    ax.set_ylabel('Number of clients')
    matplotlib.pyplot.show()
    #matplotlib.pyplot.hist(frac_both_bad)

def plot_time_to_compromise(comp_times, period_start, period_end):
    """
    Plots a histogram of times to first compromise.
    Input: comp_times: array of compromise timestamp or None
        period_start: timestamp of when simulation period started
        period_end: timestamp of when simulation period ended
    """
    time_len = float(period_end - period_start)/3600
    time_to_comp = []
    for t in comp_times:
        if (t != None):
            time_to_comp.append(float(t - period_start)/3600)
        else:
            time_to_comp.append(time_len)
    fig = matplotlib.pyplot.figure()
    ax = fig.add_subplot(111)
    ax.hist(time_to_comp, bins=50)
    ax.set_xlabel('Time to first compromise (hours)')
    ax.set_ylabel('Number of clients')
    matplotlib.pyplot.show()
    #matplotlib.pyplot.hist(frac_both_bad)


if __name__ == '__main__':
    """Plot histograms of the times to first compromise \
    and the compromise fractions for experiment with a starting\
    timestamp of [start] and an ending timestamp of [end]."""
    usage = 'Usage: pathsim_plot.py [times_in_file] \
[counts_in_file] [start] [end]'
    if (len(sys.argv) < 5):
        print(usage)
        sys.exit(1)

    times_in_file = sys.argv[1]
    counts_in_file = sys.argv[2]
# timestamps for current experiment
# 3/2/2012: 1330646400
# 4/20/2012: 1335829800    
    period_start = int(sys.argv[3])
    period_end = int(sys.argv[4])

# '#\tTime of first compromise\n'
    comp_times = []
    with open(times_in_file) as f:
        print('Plotting from file {0}'.format(times_in_file))
        f.readline() # read in header file
        for line in f:
            line_split = line[:-1].split('\t') # omit final newline
            time = int(line_split[1])
            if (time != -1):
                comp_times.append(time)
            else:
                comp_times.append(None)
    plot_time_to_compromise(comp_times, period_start, period_end)
    
# '#\tbad guard&exit\tbad guard\tbad exit\tgood\n'
    comp_cts = []
    with open(counts_in_file) as f:
        print('Plotting from file {0}'.format(counts_in_file))
        f.readline() # read in header file
        for line in f:
            cts = line[:-1].split('\t') # omit final newline
            comp_cts.append({\
               'guard_and_exit_bad':int(cts[1]),\
               'guard_only_bad':int(cts[3]),\
               'exit_only_bad':int(cts[5]),\
               'good':int(cts[7])})               
    plot_compromise_rates(comp_cts)