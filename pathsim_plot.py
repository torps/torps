# Isolate code that uses numpy and matplotlib here
# so pypy can be used with the rest.

import sys
import numpy
import matplotlib
matplotlib.use('PDF') # alerts matplotlib that display not required
import matplotlib.pyplot
#import matplotlib.mlab
import math

def plot_num_exit_fracs(self, num_exit_fracs, line_label, xlabel, title,\
    out_pathname):            
        """Helper for plot_compromise_rates that plots the compromised-rate
        CDF for a given number of compromised exits."""        
        fig = matplotlib.pyplot.figure()
        
        # histogram
        #ax = fig.add_subplot(111)
        #ax.hist(frac_both_bad, bins=30)
        #ax.set_xlabel('Fraction of compromised paths')
        #ax.set_ylabel('Number of samples')
        ##matplotlib.pyplot.hist(frac_both_bad)    
    
        for num_exit, fractions in num_exit_fracs:
            x, y = getcdf(fractions)
            matplotlib.pyplot.plot(x, y, label = '{0} {1}'.\
                format(num_exit, line_label))
        matplotlib.pyplot.xlim(xmin=0.0)
        matplotlib.pyplot.ylim(ymin=0.0)
        matplotlib.pyplot.xlabel(xlabel)
        matplotlib.pyplot.ylabel('Cumulative probability')
        matplotlib.pyplot.legend(loc='lower right')
        matplotlib.pyplot.title(title)
        matplotlib.pyplot.grid()
        
        # output    
        #matplotlib.pyplot.show()
        matplotlib.pyplot.savefig(out_pathname)                


def plot_num_exit_times(self, num_exit_times, line_label, xlabel, title,\
    out_pathname):            
        """Helper for plot_times_to_compromise that plots the
        CDF of times to compromise for a given number of compromised
        exits."""
        fig = matplotlib.pyplot.figure()
        
        # histogram
        #ax = fig.add_subplot(111)
        #ax.hist(time_to_comp, bins=30)
        #ax.set_xlabel('Time to first compromise (days)')
        #ax.set_ylabel('Number of samples')
        ##matplotlib.pyplot.hist(frac_both_bad)
    
        for num_exit, times in num_exit_times:
            x, y = getcdf(times)
            matplotlib.pyplot.plot(x, y, label = '{0} {1}'.\
                format(num_exit, line_label))
        matplotlib.pyplot.xlim(xmin=0.0)
        matplotlib.pyplot.ylim(ymin=0.0)
        matplotlib.pyplot.xlabel(xlabel)
        matplotlib.pyplot.ylabel('Cumulative probability')
        matplotlib.pyplot.legend(loc='lower right')
        matplotlib.pyplot.title(title)
        time_len = float(self.end_time - self.start_time)/float(24*60*60)
        matplotlib.pyplot.xticks(\
            numpy.arange(0, math.ceil(time_len)+1, 5))
        matplotlib.pyplot.yticks(numpy.arange(0, 1.05, .05))
        matplotlib.pyplot.grid()
    
        # output    
        #matplotlib.pyplot.show()
        matplotlib.pyplot.savefig(out_pathname)
            