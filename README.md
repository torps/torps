### Top-level simulation code:
- pathsim.py: Path simulator code. Needs Tor's stem library, consensuses, and descriptors
- congestion_aware_pathsim.py: Path simulator code for congestion-aware Tor (CAT) variant
- vcs_pathsim.py: Path simulator code for SAFEST (i.e. virtual-coordinate system) variant

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

For an example of how TorPS can be used, see
> **Users Get Routed: Traffic Correlation on Tor by Realistic Adversaries**  
> by _Aaron Johnson, Chris Wacek, Rob Jansen, Micah Sherr, and Paul Syverson_  
> To appear in Proceedings of the 20th ACM Conference on Computer and Communications Security (CCS 2013).  

The BibTeX citation for this paper is
<pre><code>@inproceedings{usersrouted-ccs13,
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
  <pre><code>python pathsim.py process [args]
  </pre></code>
  Replace [args] with "-h" for argument details. An example of this command is:
  <pre><code>python pathsim.py process --start_year 2013 --start_month 8 --end_year 2014 --end_month 7
  --in_dir in --out_dir out --slim --initial_descriptor_dir in/server-descriptors-2013-07
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
  
    If --slim is provided (recommended), then the network state files will not use the stem
  classes and will be smaller and faster to process during simulation.
  
    If the consensuses being processed start at the very beginning of a
  month, which is true assuming you just extract some monthly consensus archives as
  provided by Tor Metrics, then the --initial_descriptor_dir argument should be included
  with a directory containing the descriptors from the month *before* the first consensus month.
  If this argument is omitted, then the first ~18 hours of network state files of the first
  month of the period being processed will incorrectly contain many fewer relays than
  actually existed in the Tor network at that time. This is
  because a relay is only included if its descriptor has been found in a descriptor archive,
  but a relay only publishes a new descriptor after ~18 hours. Thus the for the
  initial hours, the needed descriptors are in the descriptor archive of the month before
  the period being processed. You can see how many relays are included in each network
  state file by looking at the output lines of the process command. For example, the
  relevant lines should look something like:
  <pre><code>Processing consensus file 2013-09-01-00-00-00-consensus
  Wrote descriptors for 2 relays.
  Did not find descriptors for 4277 relays
  </pre></code>
  Notice in this example that nearly all relays are missing descriptors here (and thus
  would not exist in the network state file), which occurred in this case because the
  consensuses to process started 2013-09-01-00-00-00 and <nobr>--initial_descriptor_dir</nobr> was
  omitted. Output from the second day of this examples shows that indeed there are no missing
  descriptors by the second day:
  <pre><code>Processing consensus file 2013-09-02-00-00-00-consensus
  ...
  Wrote descriptors for 4261 relays.
  Did not find descriptors for 0 relays
  </pre></code>
  The script util/examine_process_output.py can be fed the output of the process command
  to provide convenient statistics about the relays and descriptors produced in each network
  state file.
  2. Run simulations over a given period. This is done with the following command:
  <pre><code>python pathsim.py simulate [args]
  </pre></code>
  Replace [args] with "-h" for argument details. An example of the command for a 5000-sample simulation in which the client makes a connection to Google (74.125.131.105) every 10 minutes is:
  <pre><code>python pathsim.py simulate --nsf_dir out/ns-2013-08--2014-07 --num_samples 5000 
  --user_model simple=600 --format normal tor
  </pre></code>
  Following is another example of the command that executes a simulation in which user has "typical"
  behavior as given in the included trace file, a malicious guard relay is added with consensus
  bandwidth 15000, a malicious exit relay is added with consensus bandwidth 10000, the output
  just indicates when a malicious guard and/or exit is selected, the number of 
  client guards is adjusted to 1, and guard expiration occurs randomly between 270 and 300 days 
  after initial selection:
  <pre><code>python pathsim.py simulate --nsf_dir out/ns-2013-08--2014-07 --num_samples 5000
  --trace_file in/users2-processed.traces.pickle --user_model typical --format relay-adv
  --adv_guard_cons_bw 15000 --adv_exit_cons_bw 10000 --adv_time 0 --num_adv_guards 1
  --num_adv_exits 1 --num_guards 1 --guard_expiration 270 --loglevel INFO tor
  </pre></code>  

The included trace file (in/users2-processed.traces.pickle) includes six 20-minute traces recorded 
from a volunteer using Tor for the following activities: Facebook, Gmail / Google Chat (now 
Hangouts), Google Calendar / Google Docs, Web search, IRC, and BitTorrent. These are repeated on a
weekly schedule to create user models that fill the simulated time period. Also, a "typical" model
is created including all of  the first four (i.e. Facebook, Gmail/GChat, GCal/GDocs, Web search) in
the schedule, and "best" and "worst" models are created by replacing the TCP ports in the typical
model with port 443 and 6523, respectively. See the paper "Users Get Routed: Traffic Correlation on Tor by Realistic Adversaries" cited above for details on these traces and models.
	    
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

### Versions
The latest version of TorPS (tag "tor-0.2.4.23") simulation path selection as performed by
Tor stable release 0.2.4.23. The TorPS version at tag "tor-0.2.3.25" simulates path selection
as performed by Tor stable release 0.2.3.25.