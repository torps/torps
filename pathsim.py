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

def get_weighted_exits(bw_weights, bwweightscale, cons_rel_stats,\
    descriptors, fast, stable, internal, ip, port):
    """Returns list of fingerprints for potential exits along with
    selection weights for use in a circuit with the indicated properties."""
    
    exits = []
    
    if (port == None):
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
    
def get_weighted_middle(cons_bw_weights, cons_bwweightscale, cons_rel_stats,\
    descriptors, circ_fast, circ_stable, exit_node):
    """Returns list of fingerprints for potential middle nodes along with
    selection weights for use in a circuit with the indicated properties."""
    
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
                descriptors[fprint].address)):
            middles.append(fprint)
    # START
    # create weights
#    weights = []
#    if (internal):
#        for exit in exits:
#            bw = float(cons_rel_stats[exit].bandwidth)
#            weight = float(get_bw_weight(cons_rel_stats[exit].flags,\
#                'm',bw_weights)) / float(bwweightscale)
#            weights.append(bw * weight)
#    else:
#        for exit in exits:
#            bw = float(cons_rel_stats[exit].bandwidth)
#            weight = float(get_bw_weight(cons_rel_stats[exit].flags,\
#                'e',bw_weights)) / float(bwweightscale)
#            weights.append(bw * weight)
#    total_weight = sum(weights)
#    weighted_exits = []
#    for exit, weight in zip(exits,weights):
#        weighted_exits.append((exit,weight/total_weight))
#        
#    return weighted_exits
    

#   From dir-spec.txt
#     1. Clients SHOULD NOT use non-'Valid' or non-'Running' routers
#     2. Clients SHOULD NOT use non-'Fast' routers for any purpose other than
#       very-low-bandwidth circuits (such as introduction circuits).
#     3. Clients SHOULD NOT use non-'Stable' routers for circuits that are
#       likely to need to be open for a very long time
#     4. Clients SHOULD NOT choose non-'Guard' nodes when picking entry guard
#     5. if the [Hibernate] value is 1, then the Tor relay was hibernating when
#        the descriptor was published, and shouldn't be used to build circuits."    

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
    
def guard_filter(rel_stat):
    """Applies basic (i.e. not circuit-specific) tests to relay status
    to determine eligibility for selection as guard."""
    # [from path-spec.txt] 5. Guard nodes
    #  A guard is unusable if any of the following hold:
    #    - it is not marked as a Guard by the networkstatuses,
    #    - it is not marked Valid (and the user hasn't set AllowInvalid
    #    - it is not marked Running
    #    - Tor couldn't reach it the last time it tried to connect
    return (stem.Flag.GUARD in rel_stat.flags) and\
                (stem.Flag.VALID in rel_stat.flags) and\
                (stem.Flag.RUNNING in rel_stat.flags) # START: more needed here 
                
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

    # build a client with empty initial state  
    guards = []
    
    for c_file, d_file in zip(consensus_files, processed_descriptor_files):
        # read in descriptors and consensus statuses
        descriptors = {}
        cons_rel_stats = {}
        cons_valid_after = None
        cons_fresh_until = None
        cons_bw_weights = None
        cons_bwweightscale = None
        with open(d_file) as df, open(c_file) as cf:
            for desc in sd.parse_file(df, validate=True):
                descriptors[desc.fingerprint] = desc
            for rel_stat in sd.parse_file(cf, validate=True):
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
                    
        # go through circuit requests: (time,fast,stable,internal,ip,port)
        for circ_req in circuit_reqs:
            circ_time = circ_req[0]
            circ_fast = circ_req[1]
            circ_stable = circ_req[2]
            circ_internal = circ_req[3]
            circ_ip = circ_req[4]
            circ_port = circ_req[5]
            if (circ_time >= timestamp(cons_valid_after)) and\
                (circ_time <= timestamp(cons_fresh_until)):
                # select exit node
                weighted_exits = get_weighted_exits(cons_bw_weights, 
                    cons_bwweightscale, cons_rel_stats, descriptors, circ_fast,
                    circ_stable, circ_internal, circ_ip, circ_port)
                exit_node = select_weighted_node(weighted_exits)
                print('Exit node: {0} [{1}]'.format(
                    cons_rel_stats[exit_node].nickname,
                    cons_rel_stats[exit_node].fingerprint))
            
                # select middle node
                weighted_middle = get_weighted_middle(cons_bw_weights,
                    cons_bwweightscale, cons_rel_stats, descriptors, circ_fast,
                    circ_stable, exit_node)
                
                # select guard node
                # update guard list
                num_usable_guards = 0
                for guard in guards:
                    if (guard in cons_rel_stats) and\
                        (guard_filter(cons_rel_stats[guard])) and\
                        ((not circ_fast) or\
                            (stem.Flag.FAST in cons_rel_stats[guard].flags)) and\
                        ((not circ_stable) or\
                            (stem.Flag.STABLE in cons_rel_stats[guard].flags)):
                            # START add other circuit-specific restrictions:
                        num_usable_guards += 1
                    if (num_usable_guards < min_num_guards):
                        # add guards to end of list
                        # find unweighted potential guards
                        potential_guards = []
                        for rel_stat in cons_rel_stats.values():
                            if (guard_filter(rel_stat)):
                                potential_guards.append(rel_stat)
                        # weight discovered guards
                        # START: add more here                
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
        # (time,fast,stable,internal,ip,port)   
        circuits = [(0,True,False,False,False,None,80),
            (0,True,True,True,True,None,None),
            (0,True,True,True,True,None,None)]
        choose_paths(consensus_files, descriptor_files, circuits)
    
# TODO
# - support IPv6 addresses
# - add DNS requests