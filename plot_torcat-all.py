#!/usr/bin/python

import sys, os, numpy, matplotlib, math
from matplotlib import pyplot
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
matplotlib.rcParams.update({'figure.subplot.left': 0.14})
matplotlib.rcParams.update({'figure.subplot.right': 0.94})
matplotlib.rcParams.update({'figure.subplot.bottom': 0.25})
matplotlib.rcParams.update({'figure.subplot.top': 0.87})

def main():
    torrates, tortimes = process("typical.2012-10--2013-03.448112-82033-0-adv/data")
    catrates, cattimes = process("typical.2012-10--2013-03.448112-82033-0-adv.cat/data")
    torratesirc, tortimesirc = process("irc.2012-10--2013-03.448112-82033-0-adv/data")
    catratesirc, cattimesirc = process("irc.2012-10--2013-03.448112-1-82033-0-adv.cat/data")

    plotcdf([torrates['bothbad'], catrates['bothbad'], torratesirc['bothbad'], catratesirc['bothbad']], ["Tor-Typical", "CAT-Typical", "Tor-IRC", "CAT-IRC"], "Fraction of Streams", "Stream Compromise Rates, Guard and Exit", "lower right", "torcat-bothbad-rates-cdf-2012-10--2013-03-typical-irc.pdf")
    plotcdf([torrates['guardbad'], catrates['guardbad'], torratesirc['guardbad'], catratesirc['guardbad']], ["Tor-Typical", "CAT-Typical", "Tor-IRC", "CAT-IRC"], "Fraction of Streams", "Stream Compromise Rates, Guard Only", "lower right", "torcat-guardbad-rates-cdf-2012-10--2013-03-typical-irc.pdf")
    plotcdf([torrates['exitbad'], catrates['exitbad'], torratesirc['exitbad'], catratesirc['exitbad']], ["Tor-Typical", "CAT-Typical", "Tor-IRC", "CAT-IRC"], "Fraction of Streams", "Stream Compromise Rates, Exit Only", "lower right", "torcat-exitbad-rates-cdf-2012-10--2013-03-typical-irc.pdf")

    plotcdf([tortimes['bothbad'], cattimes['bothbad'], tortimesirc['bothbad'], cattimesirc['bothbad']], ["Tor-Typical", "CAT-Typical", "Tor-IRC", "CAT-IRC"], "Time to First Compromise (days)", "Stream Compromise Times, Guard and Exit", "lower right", "torcat-bothbad-times-cdf-2012-10--2013-03-typical-irc.pdf")
    plotcdf([tortimes['guardbad'], cattimes['guardbad'], tortimesirc['guardbad'], cattimesirc['guardbad']], ["Tor-Typical", "CAT-Typical", "Tor-IRC", "CAT-IRC"], "Time to First Compromise (days)", "Stream Compromise Times, Guard Only", "lower right", "torcat-guardbad-times-cdf-2012-10--2013-03-typical-irc.pdf")
    plotcdf([tortimes['exitbad'], cattimes['exitbad'], tortimesirc['exitbad'], cattimesirc['exitbad']], ["Tor-Typical", "CAT-Typical", "Tor-IRC", "CAT-IRC"], "Time to First Compromise (days)", "Stream Compromise Times, Exit Only", "lower right", "torcat-exitbad-times-cdf-2012-10--2013-03-typical-irc.pdf")

def main2():
    torrates, tortimes = process("typical.2012-10--2013-03.448112-82033-0-adv/data")
    catrates, cattimes = process("typical.2012-10--2013-03.448112-82033-0-adv.cat/data")
    torratesbt, tortimesbt = process("bittorrent.2012-10--2013-03.448112-82033-0-adv/data")
    catratesbt, cattimesbt = process("bittorrent.2012-10--2013-03.448112-1-82033-0-adv.cat/data")

    plotcdf([torrates['bothbad'], catrates['bothbad'], torratesbt['bothbad'], catratesbt['bothbad']], ["Tor-Typical", "CAT-Typical", "Tor-BitTorrent", "CAT-BitTorrent"], "Fraction of Streams", "Stream Compromise Rates, Guard and Exit", "lower right", "torcat-bothbad-rates-cdf-2012-10--2013-03-typical-bt.pdf")
    plotcdf([torrates['guardbad'], catrates['guardbad'], torratesbt['guardbad'], catratesbt['guardbad']], ["Tor-Typical", "CAT-Typical", "Tor-BitTorrent", "CAT-BitTorrent"], "Fraction of Streams", "Stream Compromise Rates, Guard Only", "lower right", "torcat-guardbad-rates-cdf-2012-10--2013-03-typical-bt.pdf")
    plotcdf([torrates['exitbad'], catrates['exitbad'], torratesbt['exitbad'], catratesbt['exitbad']], ["Tor-Typical", "CAT-Typical", "Tor-BitTorrent", "CAT-BitTorrent"], "Fraction of Streams", "Stream Compromise Rates, Exit Only", "lower right", "torcat-exitbad-rates-cdf-2012-10--2013-03-typical-bt.pdf")

    plotcdf([tortimes['bothbad'], cattimes['bothbad'], tortimesbt['bothbad'], cattimesbt['bothbad']], ["Tor-Typical", "CAT-Typical", "Tor-BitTorrent", "CAT-BitTorrent"], "Time to First Compromise (days)", "Stream Compromise Times, Guard and Exit", "lower right", "torcat-bothbad-times-cdf-2012-10--2013-03-typical-bt.pdf")
    plotcdf([tortimes['guardbad'], cattimes['guardbad'], tortimesbt['guardbad'], cattimesbt['guardbad']], ["Tor-Typical", "CAT-Typical", "Tor-BitTorrent", "CAT-BitTorrent"], "Time to First Compromise (days)", "Stream Compromise Times, Guard Only", "lower right", "torcat-guardbad-times-cdf-2012-10--2013-03-typical-bt.pdf")
    plotcdf([tortimes['exitbad'], cattimes['exitbad'], tortimesbt['exitbad'], cattimesbt['exitbad']], ["Tor-Typical", "CAT-Typical", "Tor-BitTorrent", "CAT-BitTorrent"], "Time to First Compromise (days)", "Stream Compromise Times, Exit Only", "lower right", "torcat-exitbad-times-cdf-2012-10--2013-03-typical-bt.pdf")

def main3():
    torrates, tortimes = process("typical.2012-10--2013-03.448112-82033-0-adv/data")
    catrates, cattimes = process("typical.2012-10--2013-03.448112-82033-0-adv.cat/data")
    torratesbt, tortimesbt = process("bittorrent.2012-10--2013-03.448112-82033-0-adv/data")
    catratesbt, cattimesbt = process("bittorrent.2012-10--2013-03.448112-1-82033-0-adv.cat/data")
    torratesirc, tortimesirc = process("irc.2012-10--2013-03.448112-82033-0-adv/data")
    catratesirc, cattimesirc = process("irc.2012-10--2013-03.448112-1-82033-0-adv.cat/data")

    plotcdf([torrates['bothbad'], catrates['bothbad'], torratesbt['bothbad'], catratesbt['bothbad'], torratesirc['bothbad'], catratesirc['bothbad']], ["Tor-Typical", "CAT-Typical", "Tor-BitTorrent", "CAT-BitTorrent", "Tor-IRC", "CAT-IRC"], "Fraction of Streams", "Stream Compromise Rates, Guard and Exit", "lower right", "torcat-bothbad-rates-cdf-2012-10--2013-03-typical-bt-irc.pdf")
    plotcdf([torrates['guardbad'], catrates['guardbad'], torratesbt['guardbad'], catratesbt['guardbad'], torratesirc['guardbad'], catratesirc['guardbad']], ["Tor-Typical", "CAT-Typical", "Tor-BitTorrent", "CAT-BitTorrent", "Tor-IRC", "CAT-IRC"], "Fraction of Streams", "Stream Compromise Rates, Guard Only", "lower right", "torcat-guardbad-rates-cdf-2012-10--2013-03-typical-bt-irc.pdf")
    plotcdf([torrates['exitbad'], catrates['exitbad'], torratesbt['exitbad'], catratesbt['exitbad'], torratesirc['exitbad'], catratesirc['exitbad']], ["Tor-Typical", "CAT-Typical", "Tor-BitTorrent", "CAT-BitTorrent", "Tor-IRC", "CAT-IRC"], "Fraction of Streams", "Stream Compromise Rates, Exit Only", "lower right", "torcat-exitbad-rates-cdf-2012-10--2013-03-typical-bt-irc.pdf")

    plotcdf([tortimes['bothbad'], cattimes['bothbad'], tortimesbt['bothbad'], cattimesbt['bothbad'], tortimesirc['bothbad'], cattimesirc['bothbad']], ["Tor-Typical", "CAT-Typical", "Tor-BitTorrent", "CAT-BitTorrent", "Tor-IRC", "CAT-IRC"], "Time to First Compromise (days)", "Stream Compromise Times, Guard and Exit", "lower right", "torcat-bothbad-times-cdf-2012-10--2013-03-typical-bt-irc.pdf")
    plotcdf([tortimes['guardbad'], cattimes['guardbad'], tortimesbt['guardbad'], cattimesbt['guardbad'], tortimesirc['guardbad'], cattimesirc['guardbad']], ["Tor-Typical", "CAT-Typical", "Tor-BitTorrent", "CAT-BitTorrent", "Tor-IRC", "CAT-IRC"], "Time to First Compromise (days)", "Stream Compromise Times, Guard Only", "lower right", "torcat-guardbad-times-cdf-2012-10--2013-03-typical-bt-irc.pdf")
    plotcdf([tortimes['exitbad'], cattimes['exitbad'], tortimesbt['exitbad'], cattimesbt['exitbad'], tortimesirc['exitbad'], cattimesirc['exitbad']], ["Tor-Typical", "CAT-Typical", "Tor-BitTorrent", "CAT-BitTorrent", "Tor-IRC", "CAT-IRC"], "Time to First Compromise (days)", "Stream Compromise Times, Exit Only", "lower right", "torcat-exitbad-times-cdf-2012-10--2013-03-typical-bt-irc.pdf")

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
    line_styles = ['-v', ':v', '-o', ':o', '-s', ':s', '-*', '-x', '-D', '-+']
    line_colors = ['b', 'b', 'g', 'g', 'r', 'r']
    num_markers = 3

    if (line_labels != None):
        i = 0
        for data_points, line_label in zip(lines, line_labels):
            # cut off points with largest value                                                          
            data_max = max(data_points)
            data_shown = filter(lambda x: x < data_max, data_points)
            shown_percentile = float(len(data_shown)) / len(data_points) if "First" in xlabel else 0.99
            #shown_percentile = 0.99
            x, y = getcdf(data_points, shown_percentile)
            matplotlib.pyplot.plot(x, y, line_styles[i % len(line_styles)], c = line_colors[i % len(line_colors)],
                label = line_label,
                linewidth = 2,
                markevery = int(math.floor(len(data_shown)/num_markers)))
            i += 1
        matplotlib.pyplot.legend(loc=location, fancybox=False, shadow=False)
    else:
        x, y = getcdf(lines)
        matplotlib.pyplot.plot(x, y)
    matplotlib.pyplot.xlim(xmin=0.0)
    #matplotlib.pyplot.xticks(numpy.arange(0, 0.02, 0.004))
    matplotlib.pyplot.locator_params(axis = 'x', nbins = 5)
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
    main() # typical, irc
    main2() # typical, bittorrent
    main3() # typical, irc, bittorrent
