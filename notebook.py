
##### Examine user traces #####
# "facebook"
# "gmailgchat"
# "gcalgdocs"
# "websearch"
# "irc"
# "bittorrent"

tracefile = 'in/traces.pickle'
tracename = 'bittorrent'

#streams =   get_user_model(start_time, end_time, 'in/traces.pickle', tracename)

f = open(tracefile)
obj = pickle.load(f)
f.close()

streams = obj.trace[tracename]

# ips and ports
ips = set()
ports = set()
for stream in streams:
    ips.add(stream[1])
    ports.add(stream[2])
    
# streams to .exit
exit_ip_streams = []
for stream in streams:
    if ('.exit' in stream[1]):
        exit_ip_streams.append(stream)

# ips to .exit
exit_ips = []
for ip in ips:
    if ('.exit' in ip):
        exit_ips.append(ip)
        
# streams to 9001
or_port_streams = []
for stream in streams:
    if (9001 == stream[2]):
        or_port_streams.append(stream)
# streams to 9001 but not to a .exit
or_port_nonexit_streams = []
for stream in streams:
    if (9001 == stream[2]) and\
        ('.exit' not in stream[1]):
        or_port_nonexit_streams.append(stream)
        
# print streams
for stream in streams:
    print('[{0:.1f}]\t{1}:{2}'.format(stream[0], stream[1], stream[2]))

# remove streams that duplicate an ip/24:port seen 10 minutes ago
max_circuit_dirtiness = 10*60
cover_time = float(max_circuit_dirtiness)/2
ip_port_seen = {}
streams_reduced = []
for stream in streams:
    ip_split = stream[1].split('.')
    ip_24 = '.'.join(ip_split[0:3])
    ip_port = ip_24 + ':' + str(stream[2])
    if (ip_port in ip_port_seen) and\
        (stream[0] - ip_port_seen[ip_port] < cover_time):
        continue
    else:
        ip_port_seen[ip_port] = stream[0]
        streams_reduced.append(stream)

### Results ###
#start_time: 1330646400
#end_time: 1335830399

#facebook
# num streams 3/12-4/12: 107081=1755.4/day
# num streams reduced (5 min. window, /24): 47
# num streams in trace: 637
# num streams to .exit: 4
# num streams to 9001 but not .exit: 0
# ips
  # num: 91
  # num w/ .exit: 4
# ports
  # num: 3
  # [80, 9001, 443]
  # to non-exit: [80, 443]
  
#gmailgchat
# num streams in trace: 516
# num streams to .exit: 0
# num streams reduced (5 min. window, /24): 40
# ips
    # num: 70
# ports
  # num: 2
  # [80, 443]
  
#gcalgdocs
# num streams in trace: 370
# num streams to .exit: 0
# num streams reduced (5 min. window, /24): 17
# ips
    # num: 42
# ports
  # num: 2
  # [80, 443]  
  
#websearch
# num streams in trace: 1343
# num streams to .exit: 0
# num streams reduced (5 min. window, /24): 138
# ips
    # num: 170
# ports
  # num: 2
  # [80, 443] 
  
#irc
# num streams in trace: 1
# num streams to .exit: 0
# ips
    # num: 1
# ports
  # num: 1
  # [6697]  
     
#bittorrent
# num streams in trace: 355
# num streams to .exit: 4
# num streams to 9001 but not .exit: 0
# num streams reduced (5 min. window, /24): 321
# ips
    # num: 285
# ports
  # num: 164  
  
  
# Model streams / week
# simple: 1008
# irc: 1 * 27 * 5 = 135
# fb: 47*4*5 = 940
# websearch: 138*4*5 = 2760
# bittorrent: 321*18*7 = 40446
#  OR 321*18*2 = 11556  
# typical (fb*7+gmail*7+gcalgdocs*7+websearch*14) = 7(47 + 40 + 17 + 2*138) = 2660
###### 

##### Finding and plotting the probabilities of compromise for the
# bandwidth-allocation experiments.
import pathsim_analysis

# guard bw : exit bw
#1:1                                                      
#5:1                                    
#10:1                                    
#50:1                                   
guard_bws = [52428800, 87381333, 95325091, 102801568]
exit_bws = [52428800, 17476267, 9532509, 2056031]
guard_cons_bws = [171394, 288115, 314643, 339610]
exit_cons_bws = [238205, 76282, 39481, 4845]

for guard_cons_bw, exit_cons_bw in zip(guard_cons_bws, exit_cons_bws):
    in_dir = 'out/analyze/typical.2013-01--03.' + guard_cons_bw + '-' + \
        exit_cons_bw + '-0-adv/data/'
#START
    (guard_comp_prob, exit_comp_prob, exit_guard_comp_prob) =\
        pathsim_analysis.compromised_set_get_compromise_prob(filename)