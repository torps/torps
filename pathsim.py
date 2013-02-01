import stem.descriptor.reader as sdr
import datetime
import os
import os.path
import stem.descriptor as sd
import stem.descriptor.networkstatus as sdn
import stem
import random
import sys

def timestamp(t):
    """Returns UNIX timestamp"""
    td = t - datetime.datetime(1970, 1, 1)
    ts = td.days*24*60*60 + td.seconds
    return ts

def process_consensuses(descriptor_dir, consensus_dir, out_dir):
    """For every input consensus, finds the descriptors published most recently before that consensus for every contained relay, and outputs that list of descriptors."""
    # read all descriptors into memory
    descriptors = {}
    num_descriptors = 0    
    num_relays = 0
    
    def skip_listener(path, event):
        print('ERROR [{0}]: {1}'.format(path, event))
    
    with sdr.DescriptorReader(descriptor_dir, validate=False) as reader:
        reader.register_skip_listener(skip_listener)
        for desc in reader:
            if (num_descriptors % 1000 == 0):
                print(num_descriptors)
            num_descriptors += 1
            if (desc.fingerprint not in descriptors):
                descriptors[desc.fingerprint] = {}
                num_relays += 1
            descriptors[desc.fingerprint][timestamp(desc.published)] = desc
#            print('Adding {0}:{1}:{2}'.format(desc.nickname,desc.fingerprint,\
#                timestamp(desc.published)))
    print('#descriptors: {0}; #relays:{1}'.format(num_descriptors,num_relays)) 

    # go through consensuses, output most recent descriptors for relays
    num_consensuses = 0
    for dirpath, dirnames, filenames in os.walk(consensus_dir):
        for filename in filenames:
            if (filename[0] != '.'):
                print(filename)
                with open(os.path.join(dirpath,filename), 'r') as cons_f:
                    relays = []
                    cons_t = None
                    for r_stat in sd.parse_file(cons_f, validate=False):
                        cons_t = r_stat.document.valid_after
                        # find descriptor published just before consensus time
                        pub_t = timestamp(r_stat.published)
                        desc_t = 0
                        # get all descriptors with this fingerprint
                        if (r_stat.fingerprint in descriptors):
                            for t in descriptors[r_stat.fingerprint].keys():
                                if (t <= pub_t) and (t >= desc_t):
                                    desc_t = t
                        if (desc_t == 0):
                            print(\
                            'Descriptor not found for {0} :\{1}:{2}'.format(\
                                r_stat.nickname,r_stat.fingerprint,pub_t))
                        else:
                            relays.append(\
                                descriptors[r_stat.fingerprint][desc_t])
                    # output all discovered descriptors
                    if cons_t:
                        outpath = os.path.join(out_dir,\
                            cons_t.strftime('%Y-%m-%d-%H-%M-%S-descriptor'))
                        f = open(outpath,'w')
                        # annotation needed for stem parser to work correctly
                        f.write('@type server-descriptor 1.0\n')                    
                        for relay in relays:
                            f.write(str(relay))
                            f.write('\n')
                        f.close()                
                    num_consensuses += 1
    print('# consensuses: {0}'.format(num_consensuses))

def get_bw_weight(flags, position, bw_weights):
    """Returns weight to apply to relay's bandwidth for given position.
        flags: list of stem.Flag values for relay from a consensus
        position: position for which to find selection weight,
             one of 'g' for guard, 'm' for middle, and 'e' for exit
        bw_weights: bandwidth_weights from NetworkStatusDocumentV3 consensus
    """
    
    if (position == 'g'):
        if (stem.Flag.GUARD in flags) and (stem.Flag.EXIT in flags):
            return bw_weights['Wgd']
        elif (stem.Flag.GUARD in flags):
            return bw_weights['Wgg']
        elif (stem.Flag.EXIT not in flags):
            return bw_weights['Wgm']
        else:
            raise ValueError('Wge weight does not exist.')
    elif (position == 'm'):
        if (stem.Flag.GUARD in flags) and (stem.Flag.EXIT in flags):
            return bw_weights['Wmd']
        elif (stem.Flag.GUARD in flags):
            return bw_weights['Wmg']
        elif (stem.Flag.EXIT in flags):
            return bw_weights['Wme']
        else:
            return bw_weights['Wmm']
    elif (position == 'e'):
        if (stem.Flag.GUARD in flags) and (stem.Flag.EXIT in flags):
            return bw_weights['Wed']
        elif (stem.Flag.GUARD in flags):
            return bw_weights['Weg']
        elif (stem.Flag.EXIT in flags):
            return bw_weights['Wee']
        else:
            return bw_weights['Wem']    
    else:
        raise ValueError('get_weight does not support position {0}.'.format(
            position))
            
def select_weighted_node(weighted_nodes):
    """Takes (node,weight) pairs, where the weights sum to 1.
    Select node with probability weight."""
    r = random.random()
    cum_prob = 0
    for node, weight in weighted_nodes:
        if (r <= cum_prob + weight):
            return node
        else:
            cum_prob += weight
    raise ValueError('Weights must sum to 1.')            

def get_weighted_exits(bw_weights, bwweightscale, cons_rel_stats,\
    descriptors, fast, stable, internal, ip, port):
    """Returns list of fingerprints for potential exits along with
    selection weights for use in a circuit with the indicated properties."""
    
    exits = []

    if (port == None) and (not internal):
        raise ValueError('get_weighted_exits() needs a port.')            

    
    for fprint in cons_rel_stats:
        rel_stat = cons_rel_stats[fprint]
        desc = descriptors[fprint]
        if (stem.Flag.BADEXIT not in rel_stat.flags) and\
            ((not fast) or (stem.Flag.FAST in rel_stat.flags)) and\
            (stem.Flag.RUNNING in rel_stat.flags) and\
            ((not stable) or (stem.Flag.STABLE in rel_stat.flags)) and\
            (stem.Flag.VALID in rel_stat.flags) and\
            (not desc.hibernating):
            if (internal):
                # An "internal" circuit, on the other hand, is one where
                # the final node is chosen just like a middle node (ignoring          
                # its exit policy).
                exits.append(fprint)
            else:
                if (ip != None) and (desc.exit_policy.can_exit_to(ip, port)):
                    exits.append(fprint)
                else:
                    can_exit = None
                    for rule in desc.exit_policy:
                        if (port >= rule.min_port) and\
                            (port <= rule.max_port) and\
                            rule.is_accept and (can_exit==None):
                            can_exit = True
                        elif (port >= rule.min_port) and\
                            (port <= rule.max_port) and\
                            (not rule.is_accept) and\
                            rule.is_address_wildcard() and (can_exit==None):
                            can_exit = False
                    if (can_exit == None): # default accept if no rule matches
                        can_exit = True                    
                    if can_exit:
                        exits.append(fprint)
    # create weights
    weights = []
    if (internal):
        for exit in exits:
            bw = float(cons_rel_stats[exit].bandwidth)
            weight = float(get_bw_weight(cons_rel_stats[exit].flags,\
                'm',bw_weights)) / float(bwweightscale)
            weights.append(bw * weight)
    else:
        for exit in exits:
            bw = float(cons_rel_stats[exit].bandwidth)
            weight = float(get_bw_weight(cons_rel_stats[exit].flags,\
                'e',bw_weights)) / float(bwweightscale)
            weights.append(bw * weight)
    total_weight = sum(weights)
    weighted_exits = []
    for exit, weight in zip(exits,weights):
        weighted_exits.append((exit,weight/total_weight))
        
    return weighted_exits
    
def in_same_family(descriptors, node1, node2):
    """Takes list of descriptors and two node fingerprints,
    checks if nodes list each other as in the same family."""
    
    desc1 = descriptors[node1]
    desc2 = descriptors[node2]
    family1 = desc1.family
    family2 = desc2.family
    node1_lists_node2 = False
    for member in family1:
        if (member == ('$'+desc2.fingerprint)) or\
            (member == desc2.nickname):
            node1_lists_node2 = True
    node2_lists_node1 = False
    for member in family2:
        if (member == ('$'+desc1.fingerprint)) or\
            (member == desc1.nickname):
            node2_lists_node1 = True
    return (node1_lists_node2 and node2_lists_node1)
    
def in_same_16_subnet(address1, address2):
    """Takes IPv4 addresses as strings and checks if the first two bytes
    are equal."""
    address1_list = address1.split('.')
    address2_list = address2.split('.')
    
    # do some address format checking
    if (len(address1_list) == 4) and\
        (len(address2_list) == 4):
        for substr in address1_list:
            if (not substr.isdigit()):
                raise ValueError(\
                    'in_same_16_subset() needs IPv4 address strings')
        for substr in address2_list:
            if (not substr.isdigit()):
                raise ValueError(\
                    'in_same_16_subset() needs IPv4 address strings')

    return (address1_list[0] == address2_list[0]) and\
        (address1_list[1] == address2_list[1])

def get_weighted_middles(bw_weights, bwweightscale, cons_rel_stats,\
    descriptors, fast, stable, exit_node, guard_node):
    """Returns list of fingerprints for potential middle nodes along with
    selection weights for use in a circuit with the indicated properties."""
    
    # filter out some nodes with zero selection probability
    # Note that we intentionally allow non-Valid routers for middle
    # as per path-spec.txt default config
    middles = []
    for fprint in cons_rel_stats:
        rel_stat = cons_rel_stats[fprint]
        desc = descriptors[fprint]
        if ((not fast) or (stem.Flag.FAST in rel_stat.flags)) and\
            (stem.Flag.RUNNING in rel_stat.flags) and\
            ((not stable) or (stem.Flag.STABLE in rel_stat.flags)) and\
            (not desc.hibernating) and\
            (exit_node != fprint) and\
            (not in_same_family(descriptors, exit_node, fprint)) and\
            (not in_same_16_subnet(descriptors[exit_node].address,\
                descriptors[fprint].address)) and\
            (guard_node != fprint) and\
            (not in_same_family(descriptors, guard_node, fprint)) and\
            (not in_same_16_subnet(descriptors[guard_node].address,\
                descriptors[fprint].address)):
            middles.append(fprint)

    # create weights
    weights = []
    for middle in middles:
        bw = float(cons_rel_stats[middle].bandwidth)
        weight = float(get_bw_weight(cons_rel_stats[middle].flags,\
            'm',bw_weights)) / float(bwweightscale)
        weights.append(bw * weight)

    total_weight = sum(weights)
    weighted_middles = []
    for middle, weight in zip(middles,weights):
        weighted_middles.append((middle,weight/total_weight))

    return weighted_middles

def guard_filter(guard, cons_rel_stats, descriptors):
    """Determines eligibility of relay for general use as guard."""
    # including both consensus and descriptor checks is redundant
    # bc process_consensuses() adds relay to consensus only if that relay's
    # descriptor will be in output file and vice versa
    if (guard in cons_rel_stats) and (guard in descriptors): 
        rel_stat = cons_rel_stats[guard]
        return (stem.Flag.GUARD in rel_stat.flags) and\
                    (stem.Flag.VALID in rel_stat.flags) and\
                    (stem.Flag.RUNNING in rel_stat.flags)
    else:
        return False
        
def guard_filter_for_circ(guard, cons_rel_stats, descriptors, fast,\
    stable, exit):
    """Adding circuit checks to standard guard filter, returns
    if guard is usable for circuit."""
    #  - liveness (although will have been checked by guard_filter)
    #  - fast/stable
    #  - not same as exit
    #  - not in exit family
    #  - not in exit /16
    
    rel_stat = cons_rel_stats[guard]
    return (guard_filter(guard, cons_rel_stats, descriptors)) and\
        (not descriptors[guard].hibernating) and\
        ((not fast) or (stem.Flag.FAST in rel_stat.flags)) and\
        ((not stable) or (stem.Flag.FAST in rel_stat.flags)) and\
        (exit != guard) and\
        (not in_same_family(descriptors, exit, guard)) and\
        (not in_same_16_subnet(descriptors[exit].address,\
                   descriptors[guard].address))

def get_new_guard(bw_weights, bwweightscale, cons_rel_stats, descriptors,\
    guards):
    """Selects a new guard that doesn't conflict with the existing list.
    Note: will raise ValueError if no suitable guard is found."""
    potential_guards = []
    for fprint in cons_rel_stats:
        if (guard_filter(fprint, cons_rel_stats, descriptors)) and\
            (not descriptors[fprint].hibernating):
            guard_conflict = False
            for guard in guards:
                if (guard == fprint) or\
                    (in_same_family(descriptors, guard, fprint)) or\
                    (in_same_16_subnet(descriptors[guard].address,\
                       descriptors[fprint].address)):
                    guard_conflict = True
                    break
            if (not guard_conflict):
                potential_guards.append(fprint)

    # create weights
    weights = []
    for potential_guard in potential_guards:
        bw = float(cons_rel_stats[potential_guard].bandwidth)
        weight = float(get_bw_weight(cons_rel_stats[potential_guard].flags,\
                    'g',bw_weights)) / float(bwweightscale)
        weights.append(bw * weight)

    total_weight = sum(weights)
    weighted_guards = []
    for potential_guard, weight in zip(potential_guards,weights):
        weighted_guards.append((potential_guard,weight/total_weight))
        
    # select new guard according to weight
    return select_weighted_node(weighted_guards)

def get_guards_for_circ(bw_weights, bwweightscale, cons_rel_stats,\
    descriptors,fast, stable, guards, num_guards, min_num_guards, exit,\
    guard_expiration_min, guard_expiration_max, circ_time):
    """Obtains needed number of live guards that will work for circuit.
    Chooses new guards if needed, and *modifies* guard list by adding them."""
    # Get live guards then add new ones until num_guards reached.
    # Slightly depart from Tor code by not considering the circuit's
    # fast or stable flags when finding live guards.
    # Tor uses fixed Stable=False and Fast=True flags when calculating # live
    # but fixed Stable=Fast=False when actually adding guards here (weirdly).
    live_guards = []
    for guard, guard_props in guards.items():
        # expire old guards here because may occur in middle of consensus hour
        if (guard_props['expires'] <= circ_time):
            print('Expiring guard: {0}'.format(guard))
            del guards[guard]
        elif (guard_props['down_since'] == None) and\
            (not descriptors[guard].hibernating):
            live_guards.append(guard)
    if (len(live_guards) < num_guards):
        for i in range(num_guards - len(live_guards)):
            new_guard = get_new_guard(bw_weights, bwweightscale,\
                cons_rel_stats, descriptors, guards)
            live_guards.append(new_guard)
            print('Need guard. Adding {0} [{1}]'.format(\
                cons_rel_stats[new_guard].nickname, new_guard))
            expiration = random.randint(guard_expiration_min,\
                guard_expiration_max)
            guards[new_guard] = {'expires':(expiration+\
                circ_time), 'down_since':None}
    
    # check for live guards that will work for this circuit
    live_guards_for_circ = filter(lambda x: guard_filter_for_circ(x,\
        cons_rel_stats, descriptors, fast, stable, exit), live_guards)
    # add new guards while there aren't enough for this circuit
    # adding is done without reference to the circuit - how Tor does it
    while (len(live_guards_for_circ) < min_num_guards):
            new_guard = get_new_guard(bw_weights, bwweightscale,\
                cons_rel_stats, descriptors, guards)
            print('Need guard for circuit. Adding {0} [{1}]'.format(\
                cons_rel_stats[new_guard].nickname, new_guard))
            expiration = random.randint(guard_expiration_min,\
                guard_expiration_max)
            guards[new_guard] = {'expires':(expiration+\
                circ_time), 'down_since':None}
            if (guard_filter_for_circ(new_guard, cons_rel_stats, descriptors,\
                fast, stable, exit)):
                live_guards_for_circ.append(new_guard)

    # choose first num_guards usable guards
    top_live_guards_for_circ = live_guards_for_circ[0:num_guards]
    if (len(top_live_guards_for_circ) < min_num_guards):
        print('Warning: Only {0} live guards for circuit.'.format(\
            len(tor_live_guards_for_circ)))
            
    return top_live_guards_for_circ

def choose_paths(consensus_files, processed_descriptor_files, circuit_reqs):
    """Creates paths for requested circuits based on the inputs consensus
    and descriptor files.
    Inputs:
        consensus_files: list of consensus filenames *in correct order*
        processed_descriptor_files: descriptors corresponding to relays in
            consensus_files as produced by process_consensuses
        circuit_reqs: list of requested circuits, where a circuit is a tuple
            (time,fast,stable,internal,ip,port), where
                time(int): seconds from time zero
                fast(bool): indicates all relay must have Fast flag
                stable(bool): indicates all relay must have Stable flag
                internal(bool): indicates is for DNS or hidden service
                ip(str): ip address of destination
                port(int): port to connect to
    """
    
    paths = []
    num_guards = 3
    min_num_guards = 2
    guard_expiration_min = 30*24*3600 # min time until guard removed from list
    guard_expiration_max = 60*24*3600 # max time until guard removed from list
    guard_down_time = 30*24*3600 # time guard can be down until is removed

    # build a client with empty initial state
    # guard is fingerprint -> {'expires':exp_time, 'down_since':down_since}
    guards = {}

    circuit_reqs.sort(key = lambda x: x[0])
    circuit_idx = 0
    
    for c_file, d_file in zip(consensus_files, processed_descriptor_files):
        print('Using consensus file {0}'.format(c_file))
        # read in descriptors and consensus statuses
        descriptors = {}
        cons_rel_stats = {}
        cons_valid_after = None
        cons_fresh_until = None
        cons_bw_weights = None
        cons_bwweightscale = None
        with open(d_file) as df, open(c_file) as cf:
            for desc in sd.parse_file(df, validate=False):
                descriptors[desc.fingerprint] = desc
            for rel_stat in sd.parse_file(cf, validate=False):
                if (cons_valid_after == None):
                    cons_valid_after = rel_stat.document.valid_after
                if (cons_fresh_until == None):
                    cons_fresh_until = rel_stat.document.fresh_until
                if (cons_bw_weights == None):
                    cons_bw_weights = rel_stat.document.bandwidth_weights
                if (cons_bwweightscale == None):
                    if ('bwweightscale' in rel_stat.document.params):
                        cons_bwweightscale = rel_stat.document.params[\
                            'bwweightscale']
                if (rel_stat.fingerprint in descriptors):
                    cons_rel_stats[rel_stat.fingerprint] = rel_stat
            if (cons_bwweightscale == None):
                # set default value
                # Yes, I could have set it initially to this value,
                # but this way, it doesn't get repeatedly set.
                cons_bwweightscale = 10000
                
        # update client state
        # set guard as down only if not present/running/valid.
        # Note: hibernating *not* considered here
        for guard, guard_props in guards.items():
            if (guard_props['down_since'] == None):
                if (guard not in cons_rel_stats):
                    print('Putting down guard {0}'.format(guard))
                    guard_props['down_since'] = timestamp(cons_valid_after)
                elif (not guard_filter(guard, cons_rel_stats, descriptors)):
                    print('Putting down guard {0}'.format(guard))
                    guard_props['down_since'] = timestamp(cons_valid_after)
            else:
                if (guard in cons_rel_stats):
                    if (guard_filter(guard, cons_rel_stats, descriptors)):
                        print('Bringing up guard {0}'.format(guard))
                        guard_props['down_since'] = None
            # remove from list if down time including this period exceeds limit
            if (guard_props['down_since'] != None):
                if (timestamp(cons_fresh_until)-guard_props['down_since'] >=\
                    guard_down_time):
                    print('Guard down too long, removing: {0}'.format(guard))
                    del guards[guard]
                    
        # go through circuit requests: (time,fast,stable,internal,ip,port)
        while (circuit_idx < len(circuit_reqs)) and\
            (circuit_reqs[circuit_idx][0] >= timestamp(cons_valid_after)) and\
                (circuit_reqs[circuit_idx][0] < timestamp(cons_fresh_until)):
            circ_time = circuit_reqs[circuit_idx][0]
            circ_fast = circuit_reqs[circuit_idx][1]
            circ_stable = circuit_reqs[circuit_idx][2]
            circ_internal = circuit_reqs[circuit_idx][3]
            circ_ip = circuit_reqs[circuit_idx][4]
            circ_port = circuit_reqs[circuit_idx][5]

            # select exit node
            weighted_exits = get_weighted_exits(cons_bw_weights, 
                cons_bwweightscale, cons_rel_stats, descriptors, circ_fast,
                circ_stable, circ_internal, circ_ip, circ_port)
            exit_node = select_weighted_node(weighted_exits)
            print('Exit node: {0} [{1}]'.format(
                cons_rel_stats[exit_node].nickname,
                cons_rel_stats[exit_node].fingerprint))
            
            # select guard node
            # get first <= num_guards guards suitable for circuit
            circ_guards = get_guards_for_circ(cons_bw_weights,\
                cons_bwweightscale, cons_rel_stats, descriptors,\
                circ_fast, circ_stable, guards, num_guards,\
                min_num_guards, exit_node, guard_expiration_min,\
                guard_expiration_max, circ_time)
            # randomly choose from among those suitable guards
            guard_node = random.choice(circ_guards)
            print('Guard node: {0} [{1}]'.format(
                cons_rel_stats[guard_node].nickname,
                cons_rel_stats[guard_node].fingerprint))
            
            
            # select middle node
            weighted_middles = get_weighted_middles(cons_bw_weights,
                cons_bwweightscale, cons_rel_stats, descriptors, circ_fast,
                circ_stable, exit_node, guard_node)
            middle_node = select_weighted_node(weighted_middles)                
            print('Middle node: {0} [{1}]'.format(
                cons_rel_stats[middle_node].nickname,
                cons_rel_stats[middle_node].fingerprint))
            
            paths.append((guard_node, middle_node, exit_node,\
                cons_rel_stats, descriptors))
                
            circuit_idx += 1
                    
    return paths
    
if __name__ == '__main__':
    command = None
    usage = 'Usage: pathsim.py [command]\nCommands:\n\tprocess: Pair consensuses with recent descriptors.\n\tsimulate: Do a bunch of simulated path selections.'
    if (len(sys.argv) <= 1):
        print(usage)
        sys.exit(1)
    else:
        command = sys.argv[1]
        if (command != 'process') and (command != 'simulate'):
            print(usage)

    if (command == 'process'):
        descriptor_dir = ['in/server-descriptors-2012-08']
        consensus_dir = 'in/consensuses-2012-08'
        out_dir = 'out/processed-descriptors-2012-08'
        process_consensuses(descriptor_dir, consensus_dir, out_dir)    
    elif (command == 'simulate'):
#        consensus_dir = 'in/consensuses'
#        descriptor_dir = 'out/descriptors'
        consensus_dir = 'tmp-cons'
        descriptor_dir = 'tmp-desc'
        
        consensus_files = []
        for dirpath, dirnames, filenames in os.walk(consensus_dir):
            for filename in filenames:
                if (filename[0] != '.'):
                    consensus_files.append(os.path.join(dirpath,filename))
        consensus_files.sort()
        
        descriptor_files = []
        for dirpath, dirnames, filenames in os.walk(descriptor_dir):
            for filename in filenames:
                if (filename[0] != '.'):
                    descriptor_files.append(os.path.join(dirpath,filename))
        descriptor_files.sort()
    
        # Specifically, on startup Tor tries to maintain one clean
        # fast exit circuit that allows connections to port 80, and at least
        # two fast clean stable internal circuits in case we get a resolve
        # request...
        # After that, Tor will adapt the circuits that it preemptively builds
        # based on the requests it sees from the user: it tries to have two
        # fast
        # clean exit circuits available for every port seen within the past
        # hour
        # (each circuit can be adequate for many predicted ports -- it doesn't
        # need two separate circuits for each port), and it tries to have the
        # above internal circuits available if we've seen resolves or hidden
        # service activity within the past hour...
        # Additionally, when a client request exists that no circuit (built or
        # pending) might support, we create a new circuit to support the
        # request.
        # For exit connections, we pick an exit node that will handle the
        # most pending requests (choosing arbitrarily among ties) 
        # (timestamp,fast,stable,internal,ip,port)   
        
        circ_time = timestamp(datetime.datetime(2012, 8, 2, 0, 0, 0))
        circuits = [(circ_time,True,False,False,None,80),
            (circ_time,True,True,True,None,None),
            (circ_time,True,True,True,None,None)]
        choose_paths(consensus_files, descriptor_files, circuits)
    
# TODO
# - support IPv6 addresses
# - add DNS requests
# - examine when guard expiration is done in tor
# - verify guard up/down calculated as in tor
# - We do not consider removing stable/fast requirements if a suitable relay can't be found at some point. Tor does this. Rather, we just error.

##### Relevant lines for path selection extracted from Tor specs.

# From dir-spec.txt
# 1. Clients SHOULD NOT use non-'Valid' or non-'Running' routers
# 2. Clients SHOULD NOT use non-'Fast' routers for any purpose other than
#    very-low-bandwidth circuits (such as introduction circuits).
# 3. Clients SHOULD NOT use non-'Stable' routers for circuits that are
#    likely to need to be open for a very long time
# 4. Clients SHOULD NOT choose non-'Guard' nodes when picking entry guard
# 5. if the [Hibernate] value is 1, then the Tor relay was hibernating when
#    the descriptor was published, and shouldn't be used to build circuits."    

# From path-spec.txt
# 1. We weight node selection according to router bandwidth
# 2. We also weight the bandwidth of Exit and Guard flagged
# nodes       
# depending on the fraction of total bandwidth that they make
#up 
# and depending upon the position they are being selected for.
# 4. IP address and port. If dest. IP is unknown, we need to
# pick    
# an exit node that "might support" connections to a
# given address port with an unknown address.  An exit node
# "might 
# support" such a connection if any clause that accepts any 
# connections to that port precedes all clauses that reject all       
# connections to that port.
# 5. We never choose an exit node flagged as "BadExit"
# ...
# 6. We do not choose the same router twice for the same path.
# 7. We do not choose any router in the same family as another in the same
#    path.
# 8. We do not choose more than one router in a given /16 subnet
#    (unless EnforceDistinctSubnets is 0).
# 9. We don't choose any non-running or non-valid router unless we have
#    been configured to do so. By default, we are configured to allow
#    non-valid routers in "middle" and "rendezvous" positions.
# 10. If we're using Guard nodes, the first node must be a Guard (see 5
#     below)
# ...
# [Sec. 5]
#  A guard is unusable if any of the following hold:
#    - it is not marked as a Guard by the networkstatuses,
#    - it is not marked Valid (and the user hasn't set AllowInvalid
#    - it is not marked Running
#    - Tor couldn't reach it the last time it tried to connect
