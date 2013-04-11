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

def plot_time_to_compromise(comp_times, period_start):
    """
    Plots a histogram of times to first compromise.
    Input: comp_times: array of compromise timestamp or None
        exp_start: timestamp of when simulation period started
    """
    time_len = float(10*max([int(stat[1]) for stat in client_stats]))/60
    time_to_comp = [float(10*(int(stat[2])-1))/60 if (int(stat[2])!=0) else time_len for stat in client_stats]
    fig = matplotlib.pyplot.figure()
    ax = fig.add_subplot(111)
    ax.hist(time_to_comp, bins=50)
    ax.set_xlabel('Time to first compromise (hours)')
    ax.set_ylabel('Number of clients')
    matplotlib.pyplot.show()
    #matplotlib.pyplot.hist(frac_both_bad)
    