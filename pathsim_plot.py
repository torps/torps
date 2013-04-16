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
##########


def plot_output_data(in_file, out_file):
    """Takes plot data output by functions in pathsim_analysis.py"""
    with open(in_file, 'rb') as f:
        data = pickle.load(f)
        line_labels = pickle.load(f)
        xlabel = pickle.load(f)
        title = pickle.load(f)

    fig = matplotlib.pyplot.figure()
    
    # histogram
    #ax = fig.add_subplot(111)
    #ax.hist(data, bins=30)
    #ax.set_xlabel('Fraction of compromised paths')
    #ax.set_ylabel('Number of samples')
    ##matplotlib.pyplot.hist(data)    
    
    if (line_labels != None):
        for data_points, line_label in zip(data, line_labels):
            x, y = getcdf(data_points)
            matplotlib.pyplot.plot(x, y, label = line_label)
        matplotlib.pyplot.legend(loc='upper left')
    else:
        x, y = getcdf(data)
        matplotlib.pyplot.plot(x, y)
    matplotlib.pyplot.xlim(xmin=0.0)
    matplotlib.pyplot.ylim(ymin=0.0)
    matplotlib.pyplot.xlabel(xlabel)
    matplotlib.pyplot.ylabel('Cumulative probability')
    matplotlib.pyplot.title(title)
    matplotlib.pyplot.grid()
    
    # output    
    #matplotlib.pyplot.show()
    matplotlib.pyplot.savefig(out_file)                

if __name__ == '__main__':
    usage = 'Usage: pathsim_plot.py [in_dir] [out_dir]\nTakes all files in in_dir, plots their contents, and outputs the results to out_dir.'
    if (len(sys.argv) < 3):
        print(usage)
        sys.exit(1)
        
    in_dir = sys.argv[1]
    out_dir = sys.argv[2]
    
    pathnames = []
    for dirpath, dirnames, fnames in os.walk(in_dir):
        for fname in fnames:
            pathnames.append(os.path.join(in_dir,fname))
    pathnames.sort()
    for in_pathname in pathnames:
        filename = os.path.basename(in_pathname)
        if (filename[0] == '.'):
            continue
        if (filename[-7:] == '.pickle'):
            out_pathname = os.path.join(out_dir, filename[:-7]+'.cdf.pdf')
        else:
            out_pathname = os.path.join(out_dir, filename+'.cdf.pdf')
        plot_output_data(in_pathname, out_pathname)