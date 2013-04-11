import numpy
import matplotlib.pyplot
import matplotlib.mlab

def plot_compromise_rates(comp_cts):
    """Plots a histogram of compromise counts as fractions.
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
    print('fraction both bad: {0}'.format(frac_both_bad))
    fig = matplotlib.pyplot.figure()
    ax = fig.add_subplot(111)
    ax.hist(frac_both_bad, bins=50)
    ax.set_xlabel('Fraction of compromised paths')
    ax.set_ylabel('Number of clients')
    matplotlib.pyplot.show()
    #matplotlib.pyplot.hist(frac_both_bad)
