# Segregating code to plot network statistics here
# so pypy can be used for most of the processing

import matplotlib
matplotlib.use('PDF') # alerts matplotlib that display not required
import matplotlib.pyplot
from network_analysis import *

def plot_against_guard_consensus_bw(initial_guards, out_dir):
    """Plot guard consensus bw against some other values."""
    guard_cons_bw = []
    guard_prob = []
    guard_avg_avg_bw = []
    guard_avg_obs_bw = []
    for fprint, guard in initial_guards.items():
        guard_cons_bw.append(guard['cons_bw'])
        guard_prob.append(guard['prob'])
        guard_avg_avg_bw.append(guard['avg_average_bandwidth'])
        guard_avg_obs_bw.append(guard['avg_observed_bandwidth'])
    fig = matplotlib.pyplot.figure()
    ax = subplot(111)
    ax.scatter(guard_cons_bw, guard_prob, label='prob')
    ax.set_xscale('log')
    ax.set_yscale('log')
    #matplotlib.pyplot.xlim(xmin=0.0)
    #matplotlib.pyplot.ylim(ymin=0.0)
    #matplotlib.pyplot.show()
    out_file = 'guard_cons_bw-prob.2013.01.01.pdf'
    out_path = os.path.join(out_dir, out_file)
    matplotlib.pyplot.savefig(out_path)
        
    fig = matplotlib.pyplot.figure()
    ax = matplotlib.pyplot.subplot(111)
    ax.scatter(guard_cons_bw, guard_avg_avg_bw, label='avg avg bw')
    ax.set_xscale('log')
    ax.set_yscale('log')
    #matplotlib.pyplot.xlim(xmin=0.0)
    #matplotlib.pyplot.ylim(ymin=0.0)    
    out_file = 'guard_cons_bw-avg_avg_bw.2013.01.01.pdf'
    out_path = os.path.join(out_dir, out_file)
    matplotlib.pyplot.savefig(out_path)
        
    fig = matplotlib.pyplot.figure()
    matplotlib.pyplot.scatter(guard_cons_bw, guard_avg_obs_bw,
        label='avg obs bw')
    matplotlib.pyplot.xlim(xmin=0.0)
    matplotlib.pyplot.ylim(ymin=0.0)    
    out_file = 'guard_cons_bw-avg_obs_bw.2013.01.01.pdf'
    out_path = os.path.join(out_dir, out_file)
    matplotlib.pyplot.savefig(out_path)
    
    # linear regression on this data
    (a, b, r_squared) = linear_regression(guard_cons_bw, guard_avg_obs_bw)
    line_x1 = 0
    line_y1 = b
    line_x2 = max(x)
    line_y2 = a*line_x2 + b
    fig = matplotlib.pyplot.figure()
    matplotlib.pyplot.scatter(guard_cons_bw, guard_avg_obs_bw,
        label='avg obs bw')
    matplotlib.pyplot.plot([line_x1, line_x2], [line_y1, line_y2])
    matplotlib.pyplot.xlim(xmin=0.0)
    matplotlib.pyplot.ylim(ymin=0.0)  
    out_file = 'guard_cons_bw-avg_obs_bw-lstsq.2013.01.01.pdf'
    out_path = os.path.join(out_dir, out_file)
    matplotlib.pyplot.savefig(out_path)
   
    