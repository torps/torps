### Top-level simulation code:
- pathsim.py: Path simulator code (aka TorPS). Needs Tor's stem library, consensuses, and descriptors
- congestion_aware_pathsim.py: Path simulator code for congestion-aware Tor (CAT) variant
- vcs_pathsim.py: Path simulator code for SAFEST variant

### Top-level analysis scripts:
- pathsim_analysis.py: Turns simulator output into statistics.
- network_analysis.py: Turns consensuses and descriptors into statistics.
- pathsim_plot.py: Turns simulator statistics into plots.
- network_plot.py: Turns network analysis statistics into plots.

### Useful shell scripts:
- run_quick_simulation.sh: Runs a simple simulation with the input paramaters
- run_simulations_cat.sh: Runs parallel CAT simulations
- run_simulations_delayed_entry.sh: Runs parallel simulations where adversary enters after start.
- run_simulations_guard_exit_bw.sh: Runs parallel simulations where guard/exit bandwidths are varied
- run_simulations_tot_bw.sh: Runs parallel simulations where total bandwidth is varied
- run_simulations_user_models.sh: Runs parallel simulations where user models are varied
- analyze_and_plot.sh: Moves simulation files around, runs analysis scripts on them, runs plot scripts on the output, archives the output.

### Directories:
- doc: Notes on COGS, stem, and Tor.
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