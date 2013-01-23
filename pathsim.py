import stem.descriptor.reader as sdr
import datetime
import os
import os.path
import stem.descriptor as sd
import stem.descriptor.networkstatus as sdn
import stem

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
    """Returns list of fingerprints for potential exists along with
    selection weights for use in a circuit with the indicated properties."""
    
    exits = []
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
                # START: do something here
                # An "internal" circuit, on the other hand, is one where
                # the final node is chosen just like a middle node (ignoring          
                # its exit policy).                
                pass
            else:
                # check exit policy for desired ip and port
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
    # add in bw weights
    weighted_exits = []
    for exit in exits:
        bw = float(cons_rel_stats[exit].bandwidth)
        weight = float(get_bw_weight(rel_stat.flags,'e',bw_weights))\
                    / float(bwweightscale)
        weighted_exits.append((exit, bw * weight))
        
    return weighted_exits

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
    # server.descriptor.server_descriptor.ServerDescriptor:
    # address, exit_policy, family,
    # average/burst/observed_bandwidth, hibernating, 
    # stem.descriptor.router_status_entry.RouterStatusEntry:
    # address, flags
    # stem.descriptor.router_status_entry.RouterStatusEntryV3
    # bandwidth, measured, exit_policy
    
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
        consensus = {}
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
                    consensus[rel_stat.fingerprint] = rel_stat
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
#     - Clients SHOULD NOT use non-'Valid' or non-'Running' routers
#     - Clients SHOULD NOT use non-'Fast' routers for any purpose other than
#       very-low-bandwidth circuits (such as introduction circuits).
#     - Clients SHOULD NOT use non-'Stable' routers for circuits that are
#       likely to need to be open for a very long time
#     - Clients SHOULD NOT choose non-'Guard' nodes when picking entry guard

                # select exit node
                weighted_exits = get_weighted_exits(cons_bw_weights, 
                    cons_bwweightscale, consensus, descriptors, circ_fast,
                    circ_stable, circ_internal, circ_ip, circ_port)
            
                # select middle node
                
                # select guard node
                # update guard list
                num_usable_guards = 0
                for guard in guards:
                    if (guard in consensus) and\
                        (guard_filter(consensus[guard])) and\
                        ((not circ_fast) or\
                            (stem.Flag.FAST in consensus[guard].flags)) and\
                        ((not circ_stable) or\
                            (stem.Flag.STABLE in consensus[guard].flags)):
                            # START add other circuit-specific restrictions:
                        num_usable_guards += 1
                    if (num_usable_guards < min_num_guards):
                        # add guards to end of list
                        # find unweighted potential guards
                        potential_guards = []
                        for rel_stat in consensus.values():
                            if (guard_filter(rel_stat)):
                                potential_guards.append(rel_stat)
                        # weight discovered guards
                        # START: add more here                
    return paths
                    

    
if __name__ == '__main__':
    descriptor_dir = ['in/server-descriptors-2012-08']
    consensus_dir = 'in/consensuses-2012-08'
    out_dir = 'out/processed-descriptors-2012-08'
    process_consensuses(descriptor_dir, consensus_dir, out_dir)    

    consensus_dir = 'in/consensuses'
    descriptor_dir = 'out/descriptors'

#    consensus_dir = 'tmp-cons'
#    descriptor_dir = 'tmp-desc'
#    consensus_files = []
#    for dirpath, dirnames, filenames in os.walk(consensus_dir):
#        for filename in filenames:
#            if (filename[0] != '.'):
#                consensus_files.append(os.path.join(dirpath,filename))
#    consensus_files.sort()
    
#    descriptor_files = []
#    for dirpath, dirnames, filenames in os.walk(descriptor_dir):
#        for filename in filenames:
#            if (filename[0] != '.'):
#                descriptor_files.append(os.path.join(dirpath,filename))
#    descriptor_files.sort()

    # Specifically, on startup Tor tries to maintain one clean
    # fast exit circuit that allows connections to port 80, and at least
    # two fast clean stable internal circuits in case we get a resolve
    # request...
    # After that, Tor will adapt the circuits that it preemptively builds
    # based on the requests it sees from the user: it tries to have two fast
    # clean exit circuits available for every port seen within the past hour
    # (each circuit can be adequate for many predicted ports -- it doesn't
    # need two separate circuits for each port), and it tries to have the
    # above internal circuits available if we've seen resolves or hidden
    # service activity within the past hour...
    # Additionally, when a client request exists that no circuit (built or
    # pending) might support, we create a new circuit to support the request.
    # For exit connections, we pick an exit node that will handle the
    # most pending requests (choosing arbitrarily among ties) 
    # (time,fast,stable,internal,ip,port)   
    circuits = [(0,True,False,False,False,None,80),
        (0,True,True,True,True,None,None),
        (0,True,True,True,True,None,None)]
#    choose_paths(consensus_files, descriptor_files, circuits)
    
# TODO
# - support IPv6 addresses
# - add DNS requests