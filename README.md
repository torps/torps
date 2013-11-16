### Top-level simulation code:
- pathsim.py: Path simulator code (aka TorPS). Needs Tor's stem library, consensuses, and descriptors
- congestion_aware_pathsim.py: Path simulator code for congestion-aware Tor (CAT) variant
- vcs_pathsim.py: Path simulator code for SAFEST variant

### Top-level analysis scripts:
- pathsim_analysis.py: Turns simulator output into statistics.
- pathsim_plot.py: Turns simulator statistics into plots.

### Useful shell scripts:
- run_quick_simulation.sh: Runs a simple simulation with the input paramaters
- run_simulations_cat.sh: Runs parallel CAT simulations
- run_simulations_delayed_entry.sh: Runs parallel simulations where adversary enters after start.
- run_simulations_guard_exit_bw.sh: Runs parallel simulations where guard/exit bandwidths are varied
- run_simulations_tot_bw.sh: Runs parallel simulations where total bandwidth is varied
- run_simulations_user_models.sh: Runs parallel simulations where user models are varied
- analyze_and_plot.sh: Moves simulation files around, runs analysis scripts on them, runs plot scripts on the output, archives the output.

### Directories:
- ext: Code for SAFEST extension
- util: Code for various useful intermediate operations

TorPS was used to produce the results in
> **Users Get Routed: Traffic Correlation on Tor by Realistic Adversaries**  
> by _Aaron Johnson, Chris Wacek, Rob Jansen, Micah Sherr, and Paul Syverson_  
> To appear in Proceedings of the 20th ACM Conference on Computer and Communications Security (CCS 2013).  

The BibTeX citation for this paper is
<pre><code>
    @inproceedings{usersrouted-ccs13,
      author = {Aaron Johnson and Chris Wacek and Rob Jansen and Micah Sherr and Paul Syverson},
      title = {Users Get Routed: Traffic Correlation on Tor by Realistic Adversaries},
      booktitle = {Proceedings of the 20th ACM Conference on Computer and Communications Security (CCS 2013)},
      year = {2013},
      publisher = {ACM}
    }
</pre></code>

### Path Simulation HOWTO
Basic path simulation can be done entirely with pathsim.py. It requires Stem
(https://stem.torproject.org/). Simulation is a two-step process:
  1. Process Tor consensuses and descriptors into a faster and more compact format for
  later path simulation. This is done with the following command:
  <pre><code>python pathsim.py process [start_year] [start_month] [end_year] [end_month] [in_dir] [out_dir] [slim] [filtered]
  </pre></code>
  An example of this is:
  <pre><code>python pathsim.py process 2012 09 2013 03 in out 1 0
  </pre></code>
    TorPS expects to find all consensuses and descriptors for a given month in the format
  and organization of the metrics.torproject.org consensus archives. Extract the
  consensus archive for a month into a directory named
  "[in-dir]/consensuses-[year]-[month]", where [year] is in YYYY format and [month]
  in is MM format. Similarly, extract the archive of descriptors for a given month into
  the directory "[in-dir]/server-descriptors-[year]-[month]".
  
    The processing command will go through each month from [start_year]/[start_month] to
  [end_year]/[end_month]. It will output the processed "network state files" for
  a given month into the directory "[out_dir]/network-state-[year]-[month]", which will
  be created if it doesn't exist.
  
    If [slim] is 1 (recommended), then the network state files will not use the stem
  classes and will be smaller and faster to process later. If [filtered] is 1 (not
  recommended by default), relays that will not be selected by the path selection
  algorithm won't be included for efficiency.
  
    IMPORTANT NOTE: If the consensuses being processed start at the very beginning of a
  month, which is true assuming you just extract some monthly consensus archives as
  provided by Tor Metrics, then the first ~18 hours of network state files for the first
  month of the period being processed will incorrectly contain many fewer relays than
  actually existed in the Tor network at that time. This is
  because a relay is only included if its descriptor is found in the descriptor archive,
  but a relay only publishes a new descriptor only after ~18 hours. Thus the for the
  initial hours, the needed descriptors are in the descriptor archive of the month before
  the period being processed. You can see how many relays are included in each network
  state file by looking at the output lines of the process command. For example, the
  relevant lines should look something like:
  <pre><code>
  Processing consensus file 2013-09-01-00-00-00-consensus
  Wrote descriptors for 2 relays.
  Did not find descriptors for 4277 relays
  </pre></code>
  Thus when doing a simulation, it is recommended to exclude the network state files from
  the first 24 hours of processing (or any longer period of time). By then, the number
  of missing descriptors should be zero or in single digits. Continuing the previous
  example, we can see there aren't any missing descriptors by the second day:
  <pre><code>
  Processing consensus file 2013-09-02-00-00-00-consensus
  ...
  Wrote descriptors for 4261 relays.
  Did not find descriptors for 0 relays
  </pre></code>
  The script util/examine_process_output.py can be fed the output of the process command
  to provide convenient statistics to help make this decision.

  found in the consensus and matched with a descriptor from the descriptor archive.
  2. Run simulations over a given period. This is done with the following command:
  <pre><code>python pathsim.py simulate [nsf dir] [# samples] [tracefile] [user model] [output]
        [adv guard cons bw] [adv exit cons bw] [adv time] [num adv guards]
        [path selection alg] [num guards] [guard expiration]       
  </pre></code>
  An example of this is:
  <pre><code>python pathsim.py simulate out/ns-2012-09--2013-03 5000 none simple=6 0 0 0 0 0 tor 3 30
  </pre></code>
  The arguments are used as follows:
	- nsf dir stores the network state files to use, default: out/network-state-files
	- # samples is the number of simulations to execute, default: 1
	- tracefile indicates the user trace. The tracefile included in TorPS is in/users2-processed.traces.pickle. default: traces.pickle
	- user model is one of "facebook", "gmailgchat", "gcalgdocs", "websearch", "irc",
	  "bittorrent", "typical", "best", "worst", "simple=[reqs/hour]", default: "simple=6"
	- output sets log level: 0 is normal, 1 is testing, 2 is for the relay adversary, 3 is
	  for the network adversary, default: 0
	- adv guard cons bw indicates the consensus bandwidth of the adversarial guard to add,
	  default: 0
	- adv exit cons bw indicates the consensus bandwidth of the adversarial exit to add,
	  default: 0
	- adv time indicates timestamp after which adv relays added toconsensuses, default: 0
    - num adv guards indicates the number of adversarial guards to add, default: 1
    - path selection alg is one of
	    - tor: uses Tor path selection, is default
		- cat [congfile]: uses congestion-aware tor with congfile is the congestion input file
		- vcs: uses the virtual-coordinate system.        
	- num guards is the number of guards TorPS will have the client maintain in the
	    guard list, default: 3
	- guard expiration indicates the time in days until the one-month period during
	    which the guard chooses a random expiration time, with 0 indicating no guard
	    expiration, default: 30
  Again, it is recommended that the network state files for the simulation should not
  include the first 24 hours of those produced by the process command to avoid the
  problem of missing descriptors described above.
	    
### Plotting Simulation Data
TorPS includes some basic functions to quickly analyze and view the results of your
simulations. Note that the shell script analyze_and_plot.sh gives an example of how to use
this functionality.
  1. pathsim_analysis.py will process a number of log files in parallel and store the
result for each one as a file containing pickled objects. It has command options:
"simulation-set" and "simulation-top". simulation-set will compute statistics for the
case that the adversary controls a set of relays. simulation-top will compute statistics
as if the adversary controls a varying number of the "top" relays. See the script output
for command options.
  2. pathsim_plot.py requires numpy and matplotlib. It takes the files output by
pathsim_analysis.py and produces a set of graphs showing the CDFs of
compromise time and rate for the guard/exit/guard&exit of user circuits. See the script
output for command options.