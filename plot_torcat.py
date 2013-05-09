#!/usr/bin/python

import sys, os, pylab, numpy, matplotlib, math
import cPickle as pickle

""" pickle format
(int) start_time: The timestamp of the first user stream during the experiment.
start = pickle.load(f)
(int) end_time: The timestamp of the last user stream during the experiment.
end = pickle.load(f)
(list) compromise_stats: A list of (dict) objects, each with the keys:
a. 'guard_only_bad': (int) the number of streams in which only the guard is malicious
b. 'exit_only_bad': (int) the number of streams in which only the exit is malicious
c. 'guard_and_exit_bad': (int) the number of streams in which both the guard and the exit are malicious
d. 'good': (int)  the number of streams in which neither the guard nor the exit is malicious
e. 'guard_only_time': (int) the timestamp of the first stream in which the guard only is malicious (possibly None)
f. 'exit_only_time' (int) the timestamp of the first stream in which the exit only is malicious (possibly None)
g. 'guard_and_exit_time':  (int) the timestamp of the first stream in both the guard and exit are malicious (possibly None)
stats = pickle.load(f)
"""

## move around the viewing scope
pylab.rcParams.update({'figure.subplot.left': 0.14})
pylab.rcParams.update({'figure.subplot.right': 0.94})
pylab.rcParams.update({'figure.subplot.bottom': 0.25})
pylab.rcParams.update({'figure.subplot.top': 0.87})

def main():
    torrates, tortimes = process("typical.2012-10--2013-03.448112-82033-0-adv/data")
    catrates, cattimes = process("typical.2012-10--2013-03.448112-82033-0-adv.cat/data")
    torrates3g, tortimes3g = process("typical.2012-10--2013-03.144618-3-82033-0-adv/data")
    catrates3g, cattimes3g = process("typical.2012-10--2013-03.144618-3-82033-0-adv.cat/data")

    plotcdf([torrates['bothbad'], catrates['bothbad'], torrates3g['bothbad'], catrates3g['bothbad']], ["Tor-1G", "CAT-1G", "Tor-3G", "CAT-3G"], "Fraction of Streams", "Stream Compromise Rates, Guard and Exit", "lower right", "torcat-bothbad-rates-cdf-typical-2012-10--2013-03.pdf")
    plotcdf([torrates['guardbad'], catrates['guardbad'], torrates3g['guardbad'], catrates3g['guardbad']], ["Tor-1G", "CAT-1G", "Tor-3G", "CAT-3G"], "Fraction of Streams", "Stream Compromise Rates, Guard Only", "lower right", "torcat-guardbad-rates-cdf-typical-2012-10--2013-03.pdf")
    plotcdf([torrates['exitbad'], catrates['exitbad']], ["Tor-1G", "CAT-1G", "Tor-3G", "CAT-3G"], "Fraction of Streams", "Stream Compromise Rates, Exit Only", "lower right", "torcat-exitbad-rates-cdf-typical-2012-10--2013-03.pdf")

    plotcdf([tortimes['bothbad'], cattimes['bothbad'], tortimes3g['bothbad'], cattimes3g['bothbad']], ["Tor-1G", "CAT-1G", "Tor-3G", "CAT-3G"], "Time to First Compromise (days)", "Stream Compromise Times, Guard and Exit", "lower right", "torcat-bothbad-times-cdf-typical-2012-10--2013-03.pdf")
    plotcdf([tortimes['guardbad'], cattimes['guardbad'], tortimes3g['guardbad'], cattimes3g['guardbad']], ["Tor-1G", "CAT-1G", "Tor-3G", "CAT-3G"], "Time to First Compromise (days)", "Stream Compromise Times, Guard Only", "lower right", "torcat-guardbad-times-cdf-typical-2012-10--2013-03.pdf")
    plotcdf([tortimes['exitbad'], cattimes['exitbad'], tortimes3g['exitbad'], cattimes3g['exitbad']], ["Tor-1G", "CAT-1G", "Tor-3G", "CAT-3G"], "Time to First Compromise (days)", "Stream Compromise Times, Exit Only", "lower right", "torcat-exitbad-times-cdf-typical-2012-10--2013-03.pdf")

def process(dirname):
    pathnames = []
    for dirpath, dirnames, fnames in os.walk(dirname):
        for fname in fnames: pathnames.append(os.path.join(dirpath,fname))
    pathnames.sort()

    # loop through once to get start and end times
    start = None
    end = None
    for pathname in pathnames:
        with open(pathname, 'rb') as f:
            start = pickle.load(f) if start is None else min(pickle.load(f), start)
            end = pickle.load(f) if end is None else max(pickle.load(f), end)
    timelen = float(end - start)/float(24*60*60)

    # now build our statistics for plotting
    rates = {'bothbad':[], 'guardbad':[], 'exitbad':[]}
    times = {'bothbad':[], 'guardbad':[], 'exitbad':[]}
    for pathname in pathnames:
        with open(pathname, 'rb') as f:
            pickle.load(f)
            pickle.load(f)
            statslist = pickle.load(f)

            for stats in statslist:
                # compromise rates
                total = float(stats['guard_and_exit_bad'] + stats['guard_only_bad'] + stats['exit_only_bad'] + stats['good'])
                rates['bothbad'].append(float(stats['guard_and_exit_bad']) / total)
                rates['exitbad'].append(float(stats['guard_and_exit_bad'] + stats['exit_only_bad']) / total)
                rates['guardbad'].append(float(stats['guard_and_exit_bad'] + stats['guard_only_bad']) / total)

                # time to first compromise
                g, e, ge = timelen, timelen, timelen
                period = float(24*60*60)
                if (stats['guard_only_time'] != None):
                    g = float(stats['guard_only_time'] - start)/period
                if (stats['exit_only_time'] != None):
                    e = float(stats['exit_only_time'] - start)/period
                if (stats['guard_and_exit_time'] != None):
                    ge = float(stats['guard_and_exit_time'] - start)/period
                    g = min(g, ge)
                    e = min(e, ge)

                times['guardbad'].append(g)
                times['exitbad'].append(e)
                times['bothbad'].append(ge)

    return rates, times            

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

def plotcdf(lines, line_labels, xlabel, title, location, out_pathname):
    """Saves cdf for given lines in out_name."""
    fig = matplotlib.pyplot.figure(figsize=(4, 1.5))
    line_styles = ['-v', '-o', '-s', '-*', '-x', '-D', '-+']
    num_markers = 5

    if (line_labels != None):
        i = 0
        for data_points, line_label in zip(lines, line_labels):
            # cut off points with largest value                                                          
            data_max = max(data_points)
            data_shown = filter(lambda x: x < data_max, data_points)
            shown_percentile = float(len(data_shown)) / len(data_points)
            #shown_percentile = 0.99
            x, y = getcdf(data_points, shown_percentile)
            matplotlib.pyplot.plot(x, y, line_styles[i % len(line_styles)],
                label = line_label,
                linewidth = 2,
                markevery = int(math.floor(len(data_shown)/num_markers)))
            i += 1
        matplotlib.pyplot.legend(loc=location, fancybox=False, shadow=False)
    else:
        x, y = getcdf(lines)
        matplotlib.pyplot.plot(x, y)
    matplotlib.pyplot.xlim(xmin=0.0)
    matplotlib.pyplot.ylim(ymin=0.0)
    matplotlib.pyplot.yticks(numpy.arange(0, 1.1, 0.2))
    matplotlib.pyplot.xlabel(xlabel)
    matplotlib.pyplot.ylabel('Cumulative Prob.')
    #matplotlib.pyplot.title(title)
    matplotlib.pyplot.grid(True)

    # output                                                                                             
    #matplotlib.pyplot.show()                                                                            
    matplotlib.pyplot.savefig(out_pathname)
##########

if __name__ == '__main__':
    main()
