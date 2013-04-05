import stem.descriptor.reader as sdr
import datetime
import os
import os.path
import stem.descriptor as sd
import stem.descriptor.networkstatus as sdn
import stem
import random
import sys
import collections
import cPickle as pickle

_testing = True

class RouterStatusEntry:
    """
    Represents a relay entry in a consensus document.
    Trim version of stem.descriptor.router_status_entry.RouterStatusEntry.
    """
    def __init__(self, fingerprint, nickname, flags, bandwidth):
        self.fingerprint = fingerprint
        self.nickname = nickname
        self.flags = flags
        self.bandwidth = bandwidth
    

class NetworkStatusDocument:
    """
    Represents a consensus document.
    Trim version of stem.descriptor.networkstatus.NetworkStatusDocument.
    """
    def __init__(self, valid_after, fresh_until, bandwidth_weights, bwweightscale, relays):
        self.valid_after = valid_after
        self.fresh_until = fresh_until
        self.bandwidth_weights = bandwidth_weights
        self.bwweightscale = bwweightscale
        self.relays = relays


class ServerDescriptor:
    """
    Represents a server descriptor.
    Trim version of stem.descriptor.server_descriptor.ServerDescriptor.
    """
    def __init__(self, fingerprint, hibernating, nickname, family, address,\
        exit_policy):
        self.fingerprint = fingerprint
        self.hibernating = hibernating
        self.nickname = nickname
        self.family = family
        self.address = address
        self.exit_policy = exit_policy


def timestamp(t):
    """Returns UNIX timestamp"""
    td = t - datetime.datetime(1970, 1, 1)
    ts = td.days*24*60*60 + td.seconds
    return ts


def process_consensuses(in_dirs):
    """For every input consensus, finds the descriptors published most recently before the descriptor times listed for the relays in that consensus, records state changes indicated by descriptors published during the consensus fresh period, and writes out pickled consensus and descriptor objects with the relevant information.
        Inputs:
            in_dirs: list of (consensus in dir, descriptor in dir, \
                processed descriptor out dir) triples *in order*
    """
    descriptors = {}
    # given by #define ROUTER_MAX_AGE (60*60*48) in or.h
    router_max_age = 60*60*48
    def skip_listener(path, event):
        print('ERROR [{0}]: {1}'.format(path, event))
        
    # read all descriptors into memory        
    for in_consensuses_dir, in_descriptors, desc_out_dir in in_dirs:
        num_descriptors = 0    
        num_relays = 0

        print('Reading descriptors from: {0}'.format(in_descriptors))
        with sdr.DescriptorReader(in_descriptors, validate=True) as reader:
            reader.register_skip_listener(skip_listener)
            for desc in reader:
                if (num_descriptors % 10000 == 0):
                    print('{0} descriptors processed.'.format(num_descriptors))
                num_descriptors += 1
                if (desc.fingerprint not in descriptors):
                    descriptors[desc.fingerprint] = {}
                    num_relays += 1
                descriptors[desc.fingerprint][timestamp(desc.published)] = desc
        print('#descriptors: {0}; #relays:{1}'.\
            format(num_descriptors,num_relays)) 

        # output pickled consensuses, dict of most recent descriptors, and 
        # list of hibernation status changes
        num_consensuses = 0
        pathnames = []
        for dirpath, dirnames, fnames in os.walk(in_consensuses_dir):
            for fname in fnames:
                pathnames.append(os.path.join(dirpath,fname))
        pathnames.sort()
        for pathname in pathnames:
            filename = os.path.basename(pathname)
            if (filename[0] == '.'):
                continue
            
            print('Processing consensus file {0}'.format(filename))
            cons_f = open(pathname, 'rb')
#                    descriptors_out = [] # replacing with object dict
            descriptors_out = {}
            hibernating_statuses = [] # (time, fprint, hibernating)
            cons_valid_after = None
            cons_fresh_until = None
            cons_bw_weights = None
            cons_bwweightscale = None
            relays = {}
            num_not_found = 0
            num_found = 0
            for r_stat in sd.parse_file(cons_f, validate=True):
                if (cons_valid_after == None):
                    cons_valid_after = r_stat.document.valid_after
                    # compute timestamp version once here
                    valid_after_ts = timestamp(cons_valid_after)
                if (cons_fresh_until == None):
                    cons_fresh_until = r_stat.document.fresh_until
                    # compute timestamp version once here
                    fresh_until_ts = timestamp(cons_fresh_until)
                if (cons_bw_weights == None):
                    cons_bw_weights = r_stat.document.bandwidth_weights
                if (cons_bwweightscale == None) and \
                    ('bwweightscale' in r_stat.document.params):
                    cons_bwweightscale = r_stat.document.params[\
                            'bwweightscale']
                relays[r_stat.fingerprint] = RouterStatusEntry(\
                    r_stat.fingerprint, r_stat.nickname, \
                    r_stat.flags, r_stat.bandwidth)
                # find most recent unexpired descriptor published before
                # the publication time in the consensus
                # and status changes in fresh period (i.e. hibernation)
                pub_time = timestamp(r_stat.published)
                desc_time = 0
                descs_while_fresh = []
                desc_time_fresh = None
                # get all descriptors with this fingerprint
                if (r_stat.fingerprint in descriptors):
                    for t,d in descriptors[r_stat.fingerprint].items():
                        # update most recent desc seen before cons pubtime
                        # allow pubtime after valid_after but not fresh_until
                        if (valid_after_ts-t <\
                            router_max_age) and\
                            (t <= pub_time) and (t > desc_time) and\
                            (t <= fresh_until_ts):
                            desc_time = t
                        # store fresh-period descs for hibernation tracking
                        if (t >= valid_after_ts) and \
                            (t <= fresh_until_ts):
                            descs_while_fresh.append((t,d))                                
                        # find most recent hibernating stat before fresh period
                        # prefer most-recent descriptor before fresh period
                        # but use oldest after valid_after if necessary
                        if (desc_time_fresh == None):
                            desc_time_fresh = t
                        elif (desc_time_fresh < valid_after_ts):
                            if (t > desc_time_fresh) and\
                                (t <= valid_after_ts):
                                desc_time_fresh = t
                        else:
                            if (t < desc_time_fresh):
                                desc_time_fresh = t

                # output best descriptor if found
                if (desc_time != 0):
# replaced with object dict                        
#                            descriptors_out.append(\
#                                descriptors[r_stat.fingerprint][desc_time])
                    num_found += 1
                    # store discovered recent descriptor
                    desc = descriptors[r_stat.fingerprint][desc_time]
                    descriptors_out[r_stat.fingerprint] = \
                        ServerDescriptor(desc.fingerprint, \
                            desc.hibernating, desc.nickname, \
                            desc.family, desc.address, \
                            desc.exit_policy) 
                            
                    # store hibernating statuses
                    if (desc_time_fresh == None):
                        raise ValueError('Descriptor error for {0}:{1}.\n Found  descriptor before published date {2}: {3}\nDid not find descriptor for initial hibernation status for fresh period starting {4}.'.format(r_stat.nickname, r_stat.fingerprint, pub_time, desc_time, valid_after_ts))
                    desc = descriptors[r_stat.fingerprint][desc_time_fresh]
                    cur_hibernating = desc.hibernating
                    hibernating_statuses.append((desc_time_fresh,\
                        desc.fingerprint, cur_hibernating))
                    if _testing:
                        if (cur_hibernating):
                            print('{0}:{1} was hibernating at consenses period start'.format(desc.nickname, desc.fingerprint))
                    descs_while_fresh.sort(key = lambda x: x[0])
                    for (t,d) in descs_while_fresh:
                        if (d.hibernating != cur_hibernating):
                            cur_hibernating = d.hibernating                                   
                            hibernating_statuses.append(\
                                (t, d.fingerprint, cur_hibernating))
                            if (cur_hibernating):
                                print('{0}:{1} started hibernating at {2}'\
                                    .format(d.nickname, d.fingerprint, t))
                            else:
                                print('{0}:{1} stopped hibernating at {2}'\
                                    .format(d.nickname, d.fingerprint, t))                   
                else:
#                            print(\
#                            'Descriptor not found for {0}:{1}:{2}'.format(\
#                                r_stat.nickname,r_stat.fingerprint, pub_time))
                    num_not_found += 1
                    
            # output pickled consensus, recent descriptors, and
            # hibernating status changes
            if (cons_valid_after != None) and\
                (cons_fresh_until != None):
                consensus = NetworkStatusDocument(cons_valid_after,\
                    cons_fresh_until, cons_bw_weights,\
                    cons_bwweightscale, relays)
                hibernating_statuses.sort(key = lambda x: x[0],\
                    reverse=True)
                outpath = os.path.join(desc_out_dir,\
                    cons_valid_after.strftime(\
                        '%Y-%m-%d-%H-%M-%S-network_state'))
                f = open(outpath, 'wb')
                pickle.dump(consensus, f, pickle.HIGHEST_PROTOCOL)
                pickle.dump(descriptors_out,f,pickle.HIGHEST_PROTOCOL)
                pickle.dump(hibernating_statuses,f,pickle.HIGHEST_PROTOCOL)
                f.close()
# replaced with pickled output
#                        outpath = os.path.join(desc_out_dir,\
#                            cons_valid_after.strftime(\
#                                '%Y-%m-%d-%H-%M-%S-descriptors'))
#                        f = open(outpath,'wb')
#                        # annotation needed for stem parser to work correctly
#                        f.write('@type server-descriptor 1.0\n')                    
#                        for desc in descriptors_out:
#                            f.write(unicode(desc).encode('utf8'))
#                            f.write('\n')
#                        f.close()

                print('Wrote descriptors for {0} relays.'.\
                    format(num_found))
                print('Did not find descriptors for {0} relays\n'.\
                    format(num_not_found))
            else:
                print('Problem parsing {0}.'.format(filename))             
            num_consensuses += 1
            
            cons_f.close()
                
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
    """Takes (node,cum_weight) pairs where non-negative cum_weight increases,
    ending at 1. Use cum_weights as cumulative probablity to select a node."""
    r = random.random()
    
    begin = 0
    end = len(weighted_nodes)-1
    mid = int((end+begin)/2)
    while True:
        if (r <= weighted_nodes[mid][1]):
            if (mid == begin):
                return weighted_nodes[mid][0]
            else:
                end = mid
                mid = int((end+begin)/2)
        else:
            if (mid == end):
                raise ValueError('Weights must sum to 1.')
            else:
                begin = mid+1
                mid = int((end+begin)/2)

    
def can_exit_to_port(descriptor, port):
    """Returns if there is *some* ip that relay will exit to port.
    Derived from compare_unknown_tor_addr_to_addr_policy() in policies.c. That
    function returns ACCEPT, PROBABLY_ACCEPT, REJECT, and PROBABLY_REJECT.
    We ignore the PRABABLY status, as is done by Tor in the uses of
    compare_unknown_tor_addr_to_addr_policy() that we care about."""             
    for rule in descriptor.exit_policy:
        if (port >= rule.min_port) and\
                (port <= rule.max_port): # assumes full range for wildcard port
            if (rule.is_address_wildcard()) or\
                (rule.get_masked_bits() == 0):
                if rule.is_accept:
                    return True
                else:
                    return False
    return True # default accept if no rule matches
    
def policy_is_reject_star(exit_policy):
    """Replicates Tor function of same name in policies.c."""
    for rule in exit_policy:
        if rule.is_accept:
            return False
        elif (((rule.min_port <= 1) and (rule.max_port == 65535)) or\
                (rule.is_port_wildcard())) and\
            ((rule.is_address_wildcard()) or (rule.get_masked_bits == 0)):
            return True
    return True

    
def filter_exits(cons_rel_stats, descriptors, fast, stable, internal, ip,\
    port):
    """Applies exit filter to relays.
    If internal, doesn't consider exit policy.
    If IP and port given, simply applies exit policy.
    If just port given, uses exit policy to guess.
    If IP and port not given, check policy for any allowed exiting. This
      behavior is for SOCKS RESOLVE requests in particular."""
    exits = []
    for fprint in cons_rel_stats:
        rel_stat = cons_rel_stats[fprint] 
        desc = descriptors[fprint]  
        if (stem.Flag.BADEXIT not in rel_stat.flags) and\
            (stem.Flag.RUNNING in rel_stat.flags) and\
            (stem.Flag.VALID in rel_stat.flags) and\
            ((not fast) or (stem.Flag.FAST in rel_stat.flags)) and\
            ((not stable) or (stem.Flag.STABLE in rel_stat.flags)):
            if (internal):
                # In an "internal" circuit final node is chosen just like a
                # middle node (ignoring its exit policy).
                exits.append(fprint)
            elif (ip != None) and\
                    (desc.exit_policy.can_exit_to(ip,\
                        port)):
                exits.append(fprint)
            elif (port != None) and\
                (can_exit_to_port(desc, port)):
                exits.append(fprint)
            elif (not policy_is_reject_star(desc.exit_policy)):
                exits.append(fprint)

    return exits

    
def get_position_weights(nodes, cons_rel_stats, position, bw_weights,\
    bwweightscale):
    """Computes the consensus "bandwidth" weighted by position weights."""
    weights = {}
    for node in nodes:
        bw = float(cons_rel_stats[node].bandwidth)
        weight = float(get_bw_weight(cons_rel_stats[node].flags,\
            position,bw_weights)) / float(bwweightscale)
        weights[node] = bw * weight
    return weights 
    
                        
def get_weighted_nodes(nodes, weights):
    """Takes list of nodes (rel_stats) and weights (as a dict) and outputs
    a list of (node, cum_weight) pairs, where cum_weight is the cumulative
    probability of the nodes weighted by weights.
    """
    # compute total weight
    total_weight = 0
    for node in nodes:
        total_weight += weights[node]
    if (total_weight == 0):
        raise ValueError('ERROR: Node list has total weight zero.')
    # create cumulative weights
    weighted_nodes = []
    cum_weight = 0
    for node in nodes:
        cum_weight += weights[node]/total_weight
        weighted_nodes.append((node, cum_weight))
    
    return weighted_nodes
           

def get_weighted_exits(bw_weights, bwweightscale, cons_rel_stats,\
    descriptors, fast, stable, internal, ip, port):
    """Returns list of (fprint,cum_weight) pairs for potential exits along with
    cumulative selection probabilities for use in a circuit with the indicated
    properties.
    """    
    # filter exit list
    exits = filter_exits(cons_rel_stats, descriptors, fast,\
        stable, internal, ip, port)
                    
    # create weights
    weights = None
    if (internal):
        weights = get_position_weights(exits, cons_rel_stats, 'm',\
                    bw_weights, bwweightscale)
    else:
        weights = get_position_weights(exits, cons_rel_stats, 'e',\
            bw_weights, bwweightscale)
            
    return get_weighted_nodes(exits, weights)           

    
def in_same_family(descriptors, node1, node2):
    """Takes list of descriptors and two node fingerprints,
    checks if nodes list each other as in the same family."""

    desc1 = descriptors[node1]
    desc2 = descriptors[node2]
    fprint1 = desc1.fingerprint
    fprint2 = desc1.fingerprint
    nick1 = desc1.nickname
    nick2 = desc2.nickname

    node1_lists_node2 = False
    for member in desc1.family:
        if ((member[0] == '$') and (member[1:] == fprint2)) or\
            (member == nick2):
            node1_lists_node2 = True

    if (node1_lists_node2):
        for member in desc2.family:
            if ((member[0] == '$') and (member[1:] == fprint1)) or\
                (member == nick1):
                return True

    return False

    
def in_same_16_subnet(address1, address2):
    """Takes IPv4 addresses as strings and checks if the first two bytes
    are equal."""
    # check first octet
    i = 0
    while (address1[i] != '.'):
        if (address1[i] != address2[i]):
            return False
        i += 1
        
    i += 1
    while (address1[i] != '.'):
        if (address1[i] != address2[i]):
            return False
        i += 1
        
    return True


def middle_filter(node, cons_rel_stats, descriptors, fast=None,\
    stable=None, exit_node=None, guard_node=None):
    """Return if candidate node is suitable as middle node. If an optional
    argument is omitted, then the corresponding filter condition will be
    skipped. This is useful for early filtering when some arguments are still
    unknown."""
    # Note that we intentionally allow non-Valid routers for middle
    # as per path-spec.txt default config    
    rel_stat = cons_rel_stats[node]
    desc = descriptors[node]
    return (stem.Flag.RUNNING in rel_stat.flags) and\
            ((fast==None) or (not fast) or\
                (stem.Flag.FAST in rel_stat.flags)) and\
            ((stable==None) or (not stable) or\
                (stem.Flag.STABLE in rel_stat.flags)) and\
            ((exit_node==None) or\
                ((exit_node != node) and\
                    (not in_same_family(descriptors, exit_node, node)) and\
                    (not in_same_16_subnet(descriptors[exit_node].address,\
                        descriptors[node].address)))) and\
            ((guard_node==None) or\
                ((guard_node != node) and\
                    (not in_same_family(descriptors, guard_node, node)) and\
                    (not in_same_16_subnet(descriptors[guard_node].address,\
                        descriptors[node].address))))
                        

def select_middle_node(bw_weights, bwweightscale, cons_rel_stats, descriptors,\
    fast, stable, exit_node, guard_node, weighted_middles=None):
    """Chooses a valid middle node by selecting randomly until one is found."""

    # create weighted middles if not given
    if (weighted_middles == None):
        middles = cons_rel_stats.keys()
        # create cumulative weighted middles
        weights = get_position_weights(middles, cons_rel_stats, 'm',\
            bw_weights, bwweightscale)
        weighted_middles = get_weighted_nodes(middles, weights)    
    
    # select randomly until acceptable middle node is found
    i = 1
    while True:
        middle_node = select_weighted_node(weighted_middles)
        if _testing:
            print('select_middle_node() made choice #{0}.'.format(i))
        i += 1
        if (middle_filter(middle_node, cons_rel_stats, descriptors, fast,\
            stable, exit_node, guard_node)):
            break
    return middle_node


def guard_is_time_to_retry(guard, time):
    """Tests if enough time has passed to retry an unreachable
    (i.e. hibernating) guard. Derived from entry_is_time_to_retry() in 
    entrynodes.c."""
    
    if (guard['last_attempted'] < guard['unreachable_since']):
        return True
    
    diff = time - guard['unreachable_since']
    if (diff < 6*60*60):
        return (time > (guard['last_attempted'] + 60*60))
    elif (diff < 3*24*60*60):
        return (time > (guard['last_attempted'] + 4*60*60))
    elif (diff < 7*24*60*60):
        return (time > (guard['last_attempted'] + 18*60*60))
    else:
        return (time > (guard['last_attempted'] + 36*60*60));


def guard_filter_for_circ(guard, cons_rel_stats, descriptors, fast,\
    stable, exit, circ_time, guards):
    """Returns if guard is usable for circuit."""
    #  - liveness (given by entry_is_live() call in choose_random_entry_impl())
    #       - not bad_since
    #       - has descriptor (although should be ensured by create_circuits()
    #       - not unreachable_since
    #  - fast/stable
    #  - not same as exit
    #  - not in exit family
    #  - not in exit /16
    # note that Valid flag not checked
    # note that hibernate status not checked (only checks unreachable_since)
    
    if (guards[guard]['bad_since'] == None):
        if (guard in cons_rel_stats) and (guard in descriptors):
            rel_stat = cons_rel_stats[guard]
            return ((not fast) or (stem.Flag.FAST in rel_stat.flags)) and\
                ((not stable) or (stem.Flag.STABLE in rel_stat.flags)) and\
                ((guards[guard]['unreachable_since'] == None) or\
                    guard_is_time_to_retry(guards[guard],circ_time)) and\
                (exit != guard) and\
                (not in_same_family(descriptors, exit, guard)) and\
                (not in_same_16_subnet(descriptors[exit].address,\
                    descriptors[guard].address))
        else:
            raise ValueError('Guard {0} not present in consensus or\ descriptors but wasn\'t marked bad.'.format(guard))
    else:
        return False


def filter_guards(cons_rel_stats, descriptors):
    """Returns relays filtered by general (non-client-specific) guard criteria.
    In particular, omits checks for IP/family/subnet conflicts within list.
    """
    guards = []
    for fprint in cons_rel_stats:
        rel_stat = cons_rel_stats[fprint]
        if (stem.Flag.RUNNING in rel_stat.flags) and\
            (stem.Flag.VALID in rel_stat.flags) and\
            (stem.Flag.GUARD in rel_stat.flags) and\
            (fprint in descriptors):
            guards.append(fprint)   
    
    return guards
    

def get_new_guard(bw_weights, bwweightscale, cons_rel_stats, descriptors,\
    client_guards, weighted_guards=None):
    """Selects a new guard that doesn't conflict with the existing list.
    Note: will raise ValueError if no suitable guard is found."""
    # - doesn't conflict with current guards
    # - running
    # - valid
    # - need guard    
    # - need descriptor, though should be ensured already by create_circuits()
    # - not single hop relay
    # follows add_an_entry_guard(NULL,0,0,for_directory) call which appears
    # in pick_entry_guards() and more directly in choose_random_entry_impl()
    if (weighted_guards == None):
        # create weighted guards
        guards = filter_guards(cons_rel_stats, descriptors)
        guard_weights = get_position_weights(guards, cons_rel_stats,\
            'g', bw_weights, bwweightscale)
        weighted_guards = get_weighted_nodes(guards, guard_weights)    
               
    # Because conflict with current guards is unlikely,
    # randomly select a guard, test, and repeat if necessary
    i = 1
    while True:
        guard_node = select_weighted_node(weighted_guards)
        if _testing:
            print('get_new_guard() made choice #{0}.'.format(i))
        i += 1

        guard_conflict = False
        for client_guard in client_guards:
            if (client_guard == guard_node) or\
                (in_same_family(descriptors, client_guard, guard_node)) or\
                (in_same_16_subnet(descriptors[client_guard].address,\
                   descriptors[guard_node].address)):
                guard_conflict = True
                break
        if (not guard_conflict):
            break

    return guard_node

def get_guards_for_circ(bw_weights, bwweightscale, cons_rel_stats,\
    descriptors, fast, stable, guards, num_guards,\
    min_num_guards, exit, guard_expiration_min, guard_expiration_max,\
    circ_time, weighted_guards=None):
    """Obtains needed number of live guards that will work for circuit.
    Chooses new guards if needed, and *modifies* guard list by adding them."""
    # Get live guards then add new ones until num_guards reached, where live is
    #  - bad_since isn't set
    #  - unreachable_since isn't set without retry
    #  - has descriptor, though create_circuits should ensure descriptor exists
    # Note that node need not have Valid flag to be live. As far as I can tell,
    # a Valid flag is needed to be added to the guard list, but isn't needed 
    # after that point.
    # Note that hibernating status is not an input here.
    # Rules derived from Tor source: choose_random_entry_impl() in entrynodes.c
    
    # add guards if not enough in list
    if (len(guards) < num_guards):
        # Oddly then only count the number of live ones
        # Slightly depart from Tor code by not considering the circuit's
        # fast or stable flags when finding live guards.
        # Tor uses fixed Stable=False and Fast=True flags when calculating # 
        # live but fixed Stable=Fast=False when adding guards here (weirdly).
        # (as in choose_random_entry_impl() and its pick_entry_guards() call)
        live_guards = filter(lambda x: (guards[x]['bad_since']==None) and\
                                (x in descriptors) and\
                                ((guards[x]['unreachable_since'] == None) or\
                                 guard_is_time_to_retry(guards[x],circ_time)),\
                            guards)
        for i in range(num_guards - len(live_guards)):
            new_guard = get_new_guard(bw_weights, bwweightscale,\
                cons_rel_stats, descriptors, guards,\
                weighted_guards)
            if _testing:                
                print('Need guard. Adding {0} [{1}]'.format(\
                    cons_rel_stats[new_guard].nickname, new_guard))
            expiration = random.randint(guard_expiration_min,\
                guard_expiration_max)
            guards[new_guard] = {'expires':(expiration+\
                circ_time), 'bad_since':None, 'unreachable_since':None,\
                'last_attempted':0, 'made_contact':False}

    # check for guards that will work for this circuit
    guards_for_circ = filter(lambda x: guard_filter_for_circ(x,\
        cons_rel_stats, descriptors, fast, stable, exit, circ_time, guards),\
        guards)
    # add new guards while there aren't enough for this circuit
    # adding is done without reference to the circuit - how Tor does it
    while (len(guards_for_circ) < min_num_guards):
            new_guard = get_new_guard(bw_weights, bwweightscale,\
                cons_rel_stats, descriptors, guards,\
                weighted_guards)
            if _testing:                
                print('Need guard for circuit. Adding {0} [{1}]'.format(\
                    cons_rel_stats[new_guard].nickname, new_guard))
            expiration = random.randint(guard_expiration_min,\
                guard_expiration_max)
            guards[new_guard] = {'expires':(expiration+\
                circ_time), 'bad_since':None, 'unreachable_since':None,\
                'last_attempted':0, 'made_contact':False}
            if (guard_filter_for_circ(new_guard, cons_rel_stats, descriptors,\
                fast, stable, exit, circ_time, guards)):
                guards_for_circ.append(new_guard)

    # return first num_guards usable guards
    return guards_for_circ[0:num_guards]


def circuit_covers_port_need(circuit, descriptors, port, need):
    """Returns if circuit satisfies a port need, ignoring the circuit
    time and need expiration."""
    return ((not need['fast']) or (circuit['fast'])) and\
            ((not need['stable']) or (circuit['stable'])) and\
            (can_exit_to_port(descriptors[circuit['path'][-1]], port))
        
        
def print_mapped_stream(client_id, circuit, stream, descriptors):
    """Prints log line showing client, time and IPs in path of stream."""
    
    guard_ip = descriptors[circuit['path'][0]].address
    middle_ip = descriptors[circuit['path'][1]].address
    exit_ip = descriptors[circuit['path'][2]].address
    if (stream['type'] == 'connect'):
        dest_ip = stream['ip']
    elif (stream['type'] == 'resolve'):
        dest_ip = 0
    else:
        raise ValueError('ERROR: Unrecognized stream in print_mapped_stream: \
{0}'.format(stream['type']))
    print('{0}\t{1}\t{2}\t{3}\t{4}\t{5}'.format(client_id, stream['time'],\
        guard_ip, middle_ip, exit_ip, dest_ip))

def circuit_supports_stream(circuit, stream, long_lived_ports, descriptors):
    """Returns if stream can run over circuit (which is assumed live)."""

    if (stream['type'] == 'connect'):
        if (stream['ip'] == None):
            raise ValueError('Stream must have ip.')
        if (stream['port'] == None):
            raise ValueError('Stream must have port.')
    
        desc = descriptors[circuit['path'][-1]]
        if (desc.exit_policy.can_exit_to(stream['ip'], stream['port'])) and\
            (not circuit['internal']) and\
            ((circuit['stable']) or\
                (stream['port'] not in long_lived_ports)):
            return True
        else:
            return False
    elif (stream['type'] == 'resolve'):
        desc = descriptors[circuit['path'][-1]]
        if (not policy_is_reject_star(desc.exit_policy)) and\
            (not circuit['internal']):
            return True
        else:
            return False
    else:
        raise ValueError('ERROR: Unrecognized stream in \
circuit_supports_stream: {0}'.format(stream['type']))

        
def uncover_circuit_ports(circuit, port_needs_covered, _testing):
    """Reduces cover count for ports that circuit indicates it covers."""
    for port in circuit['covering']:
        if (port in port_needs_covered):
            port_needs_covered[port] -= 1
            if _testing:                                                
                print('Decreased cover count for port {0} to {1}.'.\
format(port, port_needs_covered[port]))
        else:
            if _testing:                                        
                print('Port {0} not found in port_needs_covered'.format(port))
    
    
def kill_circuits_by_relay(client_state, relay_down_fn, _testing):
    """Kill circuits with a relay that is down as judged by relay_down_fn."""    
    # go through dirty circuits
    new_dirty_exit_circuits = collections.deque()
    while(len(client_state['dirty_exit_circuits']) > 0):
        circuit = client_state['dirty_exit_circuits'].popleft()
        circuit_live = True
        for i in range(len(circuit['path'])):
            relay = circuit['path'][i]
            if relay_down_fn(relay):
                circuit_live = False
                break
        if (circuit_live):
            new_dirty_exit_circuits.append(circuit)
        else:
            if (_testing):
                print('Killing dirty circuit because a relay is down.')
    client_state['dirty_exit_circuits'] = new_dirty_exit_circuits
    # go through clean circuits
    new_clean_exit_circuits = collections.deque()
    while(len(client_state['clean_exit_circuits']) > 0):
        circuit = client_state['clean_exit_circuits'].popleft()
        circuit_live = True
        for i in range(len(circuit['path'])):
            relay = circuit['path'][i]
            if relay_down_fn(relay):
                circuit_live = False
                break
        if (circuit_live):
            new_clean_exit_circuits.append(circuit)
        else:
            if (_testing):
                print('Killing clean circuit because a relay is down')
            uncover_circuit_ports(circuit, client_state['port_needs_covered'],\
                _testing)
    client_state['clean_exit_circuits'] = new_clean_exit_circuits

            

def timed_client_updates(cur_time, client_state, num_guards, min_num_guards,\
    guard_expiration_min, guard_expiration_max, max_circuit_dirtiness,\
    circuit_idle_timeout, max_unused_open_circuits, port_needs_global,\
    cons_rel_stats, cons_valid_after,\
    cons_fresh_until, cons_bw_weights, cons_bwweightscale, descriptors,\
    hibernating_status, port_need_weighted_exits, weighted_middles,\
    weighted_guards, _testing):
    """Performs updates to client state that occur on a time schedule."""
    
    if _testing:
        print('Client {0} timed update.'.\
            format(client_state['id']))
    guards = client_state['guards']
            
    # kill old dirty circuits
    while (len(client_state['dirty_exit_circuits'])>0) and\
            (client_state['dirty_exit_circuits'][-1]['dirty_time'] <=\
                cur_time - max_circuit_dirtiness):
        if _testing:
            print('Killed dirty exit circuit at time {0} w/ dirty time \
{1}'.format(cur_time, client_state['dirty_exit_circuits'][-1]['dirty_time']))
        client_state['dirty_exit_circuits'].pop()
        
    # kill old clean circuits
    while (len(client_state['clean_exit_circuits'])>0) and\
            (client_state['clean_exit_circuits'][-1]['time'] <=\
                cur_time - circuit_idle_timeout):
        if _testing:
            print('Killed clean exit circuit at time {0} w/ time \
{1}'.format(cur_time, client_state['clean_exit_circuits'][-1]['time']))
        uncover_circuit_ports(client_state['clean_exit_circuits'][-1],\
            client_state['port_needs_covered'], _testing)
        client_state['clean_exit_circuits'].pop()
        
    # kill circuits with relays that have gone into hibernation
    kill_circuits_by_relay(client_state, \
        lambda r: hibernating_status[r], _testing)
                  
    # cover uncovered ports while fewer than max_unused_open_circuits clean
    for port, need in port_needs_global.items():
        if (client_state['port_needs_covered'][port] < need['cover_num']):
            # we need to make new circuits
            # note we choose circuits specifically to cover all port needs,
            #  while Tor makes one circuit (per sec) that covers *some* port
            #  (see circuit_predict_and_launch_new() in circuituse.c)
            if _testing:                                
                print('Creating {0} circuit(s) at time {1} to cover port \
{2}.'.format(need['cover_num']-client_state['port_needs_covered'][port],\
 cur_time, port))
            while (client_state['port_needs_covered'][port] <\
                    need['cover_num']) and\
                (len(client_state['clean_exit_circuits']) < \
                    max_unused_open_circuits):
                new_circ = create_circuit(cons_rel_stats,\
                    cons_valid_after, cons_fresh_until,\
                    cons_bw_weights, cons_bwweightscale,\
                    descriptors, hibernating_status, guards, cur_time,\
                    need['fast'], need['stable'], False, None, port,\
                    num_guards, min_num_guards, guard_expiration_min,\
                    guard_expiration_max, port_need_weighted_exits[port],\
                    weighted_middles, weighted_guards)                    
                client_state['clean_exit_circuits'].appendleft(new_circ)
                
                # cover this port and any others
                client_state['port_needs_covered'][port] += 1
                new_circ['covering'].append(port)
                for pt, nd in port_needs_global.items():
                    if (pt != port) and\
                        (circuit_covers_port_need(new_circ,\
                            descriptors, pt, nd)):
                        client_state['port_needs_covered'][pt] += 1
                        new_circ['covering'].append(pt)
        
        
def client_assign_stream(client_state, stream, cons_rel_stats,\
    cons_valid_after, cons_fresh_until, cons_bw_weights, cons_bwweightscale,\
    descriptors, hibernating_status, num_guards, min_num_guards,\
    guard_expiration_min, guard_expiration_max, stream_weighted_exits,\
    weighted_middles, weighted_guards, long_lived_ports, _testing):
    """Assigns a stream to a circuit for a given client."""
        
    guards = client_state['guards']
    stream_assigned = None

    # try to use a dirty circuit
    for circuit in client_state['dirty_exit_circuits']:
        if circuit_supports_stream(circuit, stream,\
            long_lived_ports, descriptors):
            stream_assigned = circuit
            if _testing:                                
                if (stream['type'] == 'connect'):
                    print('Assigned CONNECT stream to port {0} to \
    dirty circuit at {1}'.format(stream['port'], stream['time']))
                elif (stream['type'] == 'resolve'):
                    print('Assigned RESOLVE stream to dirty circuit \
    at {0}'.format(stream['time']))
                else:
                    print('Assigned unrecognized stream to dirty circuit \
    at {0}'.format(stream['time']))                                   
            break        
    # next try and use a clean circuit
    if (stream_assigned == None):
        new_clean_exit_circuits = collections.deque()
        while (len(client_state['clean_exit_circuits']) > 0):
            circuit = client_state['clean_exit_circuits'].popleft()
            if (circuit_supports_stream(circuit, stream,\
                long_lived_ports, descriptors)):
                stream_assigned = circuit
                circuit['dirty_time'] = stream['time']
                client_state['dirty_exit_circuits'].appendleft(circuit)
                new_clean_exit_circuits.extend(\
                    client_state['clean_exit_circuits'])
                client_state['clean_exit_circuits'].clear()
                if _testing:
                    if (stream['type'] == 'connect'):
                        print('Assigned CONNECT stream to port {0} to \
clean circuit at {1}'.format(stream['port'], stream['time']))
                    elif (stream['type'] == 'resolve'):
                        print('Assigned RESOLVE stream to clean circuit \
at {0}'.format(stream['time']))
                    else:
                        print('Assigned unrecognized stream to clean circuit \
at {0}'.format(stream['time']))
                    
                # reduce cover count for covered port needs
                uncover_circuit_ports(circuit,\
                    client_state['port_needs_covered'], _testing)
            else:
                new_clean_exit_circuits.append(circuit)
        client_state['clean_exit_circuits'] =\
            new_clean_exit_circuits
    # if stream still unassigned we must make new circuit
    if (stream_assigned == None):
        new_circ = None
        if (stream['type'] == 'connect'):
            stable = (stream['port'] in long_lived_ports)
            new_circ = create_circuit(cons_rel_stats,\
                cons_valid_after, cons_fresh_until,\
                cons_bw_weights, cons_bwweightscale,\
                descriptors, hibernating_status, guards, stream['time'], True,\
                stable, False, stream['ip'], stream['port'],\
                num_guards, min_num_guards, guard_expiration_min,\
                guard_expiration_max, stream_weighted_exits, weighted_middles,\
                weighted_guards)
        elif (stream['type'] == 'resolve'):
            stable = (stream['port'] in long_lived_ports)
            new_circ = create_circuit(cons_rel_stats,\
                cons_valid_after, cons_fresh_until,\
                cons_bw_weights, cons_bwweightscale,\
                descriptors, hibernating_status, guards, stream['time'], True,\
                False, False, None, None,\
                num_guards, min_num_guards, guard_expiration_min,\
                guard_expiration_max, stream_weighted_exits, weighted_middles,\
                weighted_guards)
        else:
            raise ValueError('Unrecognized stream in client_assign_stream(): \
{0}'.format(stream['type']))        
        new_circ['dirty_time'] = stream['time']
        stream_assigned = new_circ
        client_state['dirty_exit_circuits'].appendleft(new_circ)
        if _testing: 
            if (stream['type'] == 'connect'):                           
                print('Created circuit at time {0} to cover CONNECT \
stream to ip {1} and port {2}.'.format(stream['time'], stream['ip'],\
stream['port'])) 
            elif (stream['type'] == 'resolve'):
                print('Created circuit at time {0} to cover RESOLVE \
stream.'.format(stream['time']))
            else: 
                print('Created circuit at time {0} to cover unrecognized \
stream.'.format(stream['time']))

    return stream_assigned


def create_circuit(cons_rel_stats, cons_valid_after, cons_fresh_until,\
    cons_bw_weights, cons_bwweightscale, descriptors, hibernating_status,\
    guards, circ_time, circ_fast, circ_stable, circ_internal, circ_ip,\
    circ_port, num_guards, min_num_guards, guard_expiration_min,\
    guard_expiration_max, weighted_exits=None, weighted_middles=None,\
    weighted_guards=None):
    """Creates path for requested circuit based on the input consensus
    statuses and descriptors.
    Inputs:
        cons_rel_stats: (dict) relay fingerprint keys and relay status vals
        cons_valid_after: (int) timestamp of valid_after for consensus
        cons_fresh_until: (int) timestamp of fresh_until for consensus
        cons_bw_weights: (dict) bw_weights of consensus
        cons_bwweightscale: (should be float()able) bwweightscale of consensus
        descriptors: (dict) relay fingerprint keys and descriptor vals
        hibernating_status: (dict) indicates hibernating relays
        guards: (dict) contains guards of requesting client
        circ_time: (int) timestamp of circuit request
        circ_fast: (bool) all relays should be fast
        circ_stable: (bool) all relays should be stable
        circ_internal: (bool) circuit is for name resolution or hidden service
        circ_ip: (str) IP address of destination (None if not known)
        circ_port: (int) desired TCP port (None if not known)
        num_guards - guard_expiration_max: various Tor parameters
        weighted_exits: (list) (middle, cum_weight) pairs for exit position
        weighted_middles: (list) (middle, cum_weight) pairs for middle position
    Output:
        circuit: (dict) a newly created circuit with keys
            'time': (int) seconds from time zero
            'fast': (bool) relays must have Fast flag
            'stable': (bool) relays must have Stable flag
            'internal': (bool) is internal (e.g. for hidden service)
            'dirty_time': (int) timestamp of time dirtied, None if clean
            'path': (tuple) list in-order fingerprints for path's nodes
            'cons_rel_stats': (dict) relay stats for active consensus
            'covering': (list) ports with needs covered by circuit        
    """
    
    if (circ_time < cons_valid_after) or\
        (circ_time >= cons_fresh_until):
        raise ValueError('consensus not fresh for circ_time in create_circuit')
 
    # select exit node
    if (weighted_exits == None):
        weighted_exits = get_weighted_exits(cons_bw_weights, 
            cons_bwweightscale, cons_rel_stats, descriptors, circ_fast,
            circ_stable, circ_internal, circ_ip, circ_port)
    i = 1
    while (True):
        exit_node = select_weighted_node(weighted_exits)
        if (not hibernating_status[exit_node]):
            break
        if _testing:
            print('Exit selection #{0} is hibernating - retrying.'.format(i))
        i += 1
    if _testing:    
        print('Exit node: {0} [{1}]'.format(
            cons_rel_stats[exit_node].nickname,
            cons_rel_stats[exit_node].fingerprint))
    
    # select guard node
    # Hibernation status again checked here to reflect how in Tor
    # new guards would be chosen and added to the list prior to a circuit-
    # creation attempt. If the circuit fails at a new guard, that guard
    # gets removed from the list.
    while True:
        # get first <= num_guards guards suitable for circuit
        circ_guards = get_guards_for_circ(cons_bw_weights,\
            cons_bwweightscale, cons_rel_stats, descriptors,\
            circ_fast, circ_stable, guards, num_guards,\
            min_num_guards, exit_node, guard_expiration_min,\
            guard_expiration_max, circ_time, weighted_guards)   
        guard_node = random.choice(circ_guards)
        if (hibernating_status[guard_node]):
            if (not guards[guard_node]['made_contact']):
                if _testing:
                    print('[Time {0}]: Removing new hibernating guard: {1}.'.\
                        format(circ_time, cons_rel_stats[guard_node].nickname))
                del guards[guard_node]
            elif (guards[guard_node]['unreachable_since'] != None):
                if _testing:
                    print('[Time {0}]: Guard retried but hibernating: {1}'.\
                        format(circ_time, cons_rel_stats[guard_node].nickname))
                guards[guard_node]['last_attempted'] = circ_time
            else:
                if _testing:
                    print('[Time {0}]: Guard newly hibernating: {1}'.\
                        format(circ_time, cons_rel_stats[guard_node].nickname))
                guards[guard_node]['unreachable_since'] = circ_time
                guards[guard_node]['last_attempted'] = circ_time
        else:
            guards[guard_node]['unreachable_since'] = None
            guards[guard_node]['made_contact'] = True
            break
    if _testing:
        print('Guard node: {0} [{1}]'.format(
            cons_rel_stats[guard_node].nickname,
            cons_rel_stats[guard_node].fingerprint))
    
    # select middle node
    # As with exit selection, hibernating status checked here to mirror Tor
    # selecting middle, having the circuit fail, reselecting a path,
    # and attempting circuit creation again.    
    i = 1
    while (True):
        middle_node = select_middle_node(cons_bw_weights, cons_bwweightscale,\
            cons_rel_stats, descriptors, circ_fast,\
            circ_stable, exit_node, guard_node, weighted_middles)
        if (not hibernating_status[middle_node]):
            break
        if _testing:
            print('Middle selection #{0} is hibernating - retrying.'.format(i))
        i += 1    
    if _testing:
        print('Middle node: {0} [{1}]'.format(
            cons_rel_stats[middle_node].nickname,
            cons_rel_stats[middle_node].fingerprint))
    
    return {'time':circ_time,\
            'fast':circ_fast,\
            'stable':circ_stable,\
            'internal':circ_internal,\
            'dirty_time':None,\
            'path':(guard_node, middle_node, exit_node),\
            'cons_rel_stats':cons_rel_stats,\
            'covering':[]}
    
# Replaced arguments with network_state_files.    
#def create_circuits(relstats_files, processed_descriptor_files, streams,\
#    num_samples):
def create_circuits(network_state_files, streams, num_samples):
    """Takes streams over time and creates circuits by interaction
    with choose_path().
      Input:
        *** Replaced these with network_state_file arguments. ***
        relstats_files: list of filenames with consensuses
                        *in correct order*, must exactly cover a time period
                        (i.e. no gaps or overlaps)
        processed_descriptor_files: list of filenames with descriptors
            corresponding to relays in relstats_files as produced by
            process_consensuses      
        ******
        network_state_files: list of filenames with network statuses
            as produced by process_consensuses        
        streams: *ordered* list of streams, where a stream is a dict with keys
            'time': timestamp of when stream request occurs 
            'type': 'connect' for SOCKS CONNECT, 'resolve' for SOCKS RESOLVE
            'ip': IP address of destination
            'port': desired TCP port
        num_samples: (int) # circuit-creation samples to take for given streams
    Output:
        [Prints circuit and guard selections of clients.]
    """
    
    ### Tor parameters ###
    num_guards = 3
    min_num_guards = 2
    guard_expiration_min = 30*24*3600 # min time until guard removed from list
    guard_expiration_max = 60*24*3600 # max time until guard removed from list    
    
    # max age of a dirty circuit to which new streams can be assigned
    # set by MaxCircuitDirtiness option in Tor (default: 10 min.)
    max_circuit_dirtiness = 10*60
    
    # max age of a clean circuit
    # set by CircuitIdleTimeout in Tor (default: 60 min.)
    circuit_idle_timeout = 60*60
    
    # max number of preemptive clean circuits
    # given with "#define MAX_UNUSED_OPEN_CIRCUITS 14" in Tor's circuituse.c
    max_unused_open_circuits = 14
    
    # long-lived ports (taken from path-spec.txt)
    long_lived_ports = [21, 22, 706, 1863, 5050, 5190, 5222, 5223, 6667,\
        6697, 8300]
        
    # observed port creates a need active for a limited amount of time
    # given with "#define PREDICTED_CIRCS_RELEVANCE_TIME 60*60" in rephist.c
    # need expires after an hour
    port_need_lifetime = 60*60 

    # time a guard can stay down until it is removed from list    
    # set by #define ENTRY_GUARD_REMOVE_AFTER (30*24*60*60) in entrynodes.c
    guard_down_time = 30*24*60*60 # time guard can be down until is removed
    
    # needs that apply to all samples
    # min coverage given with "#define MIN_CIRCUITS_HANDLING_STREAM 2" in or.h
    port_need_cover_num = 2
    ### End Tor parameters ###
    
    port_needs_global = {}

    ### Client states for each sample ###
    client_states = []
    for i in range(num_samples):
        # guard is fingerprint -> {'expires':exp_time, 'bad_since':bad_since}
        # port_needs are ports that must be covered by existing circuits        
        # circuit vars are ordered by increasing time since create or dirty
        port_needs_covered = {}
        client_states.append({'id':i,
                            'guards':{},
                            'port_needs_covered':port_needs_covered,
                            'clean_exit_circuits':collections.deque(),
                            'dirty_exit_circuits':collections.deque()})
    
    ### Simulation variables ###
    cur_period_start = None
    cur_period_end = None
    stream_start = 0
    stream_end = 0
    init = True
    
    if (not _testing):
        print('Sample\tTimestamp\tGuard IP\tMiddle IP\tExit IP\tDestination\
 IP')

     # store old descriptors (for entry guards that leave consensus)    
    descriptors = {}
    # run simulation period one pair of consensus/descriptor files at a time
# Replaced with network_state_files.
#    for r_file, d_file in zip(relstats_files, processed_descriptor_files):
    for ns_file in network_state_files:
# Replaced with network states    
#        # read in descriptors and consensus statuses
        # read in network states
        if _testing:
            print('Using file {0}'.format(ns_file))
        cons_valid_after = None
        cons_fresh_until = None
        cons_bw_weights = None
        cons_bwweightscale = None        
        cons_rel_stats = {}
        hibernating_statuses = None
        hibernating_status = {}
# replaced with network_state_files        
#        with open(d_file, 'r') as df, open(r_file, 'r') as cf:
        with open(ns_file, 'r') as nsf:
            """Replaced with network_state_files.
            for desc in sd.parse_file(df, validate=False):
                descriptors[desc.fingerprint] = desc
            for rel_stat in sd.parse_file(cf, validate=False):
                if (cons_valid_after == None):
                    cons_valid_after = \
                        timestamp(rel_stat.document.valid_after)
                    if (cur_period_start == None):
                        cur_period_start = cons_valid_after
                    elif (cur_period_end == cons_valid_after):
                        cur_period_start = cons_valid_after
                    else:
                        err = 'Gap/overlap in consensus times: {0}:{1}'.\
                                format(cur_period_end, cons_valid_after)
                        raise ValueError(err)
                if (cons_fresh_until == None):
                    cons_fresh_until = \
                        timestamp(rel_stat.document.fresh_until)
                    cur_period_end = cons_fresh_until
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
            """
            consensus = pickle.load(nsf)
            descriptors.update(pickle.load(nsf))
            hibernating_statuses = pickle.load(nsf)
            
            # set variables from consensus
            cons_valid_after = timestamp(consensus.valid_after)            
            cons_fresh_until = timestamp(consensus.fresh_until)
            cons_bw_weights = consensus.bandwidth_weights
            if (consensus.bwweightscale == None):
                cons_bwweightscale = 10000
            else:
                cons_bwweightscale = consensus.bwweightscale
            for relay in consensus.relays:
                if (relay in descriptors):
                    cons_rel_stats[relay] = consensus.relays[relay]

        # update simulation period                
        if (cur_period_start == None):
            cur_period_start = cons_valid_after
        elif (cur_period_end == cons_valid_after):
            cur_period_start = cons_valid_after
        else:
            err = 'Gap/overlap in consensus times: {0}:{1}'.\
                    format(cur_period_end, cons_valid_after)
            raise ValueError(err)
        cur_period_end = cons_fresh_until  

        # set initial hibernating status
        while (hibernating_statuses) and\
            (hibernating_statuses[-1][0] <= cur_period_start):
            hs = hibernating_statuses.pop()
            hibernating_status[hs[1]] = hs[2]
            if _testing:
                if (hs[2]):
                    print('{0} was hibernating at start of consensus period.'.\
                        format(cons_rel_stats[hs[1]].nickname))
        
        if (init == True): # first period in simulation
            # seed port need
            port_needs_global[80] = \
                {'expires':(cur_period_start+port_need_lifetime), 'fast':True,\
                'stable':False, 'cover_num':port_need_cover_num}
            for client_state in client_states:
                client_state['port_needs_covered'][80] = 0
            init = False
        
        
        # Update client state based on relay status changes in new consensus by
        #  updating guard list and killing existing circuits.
        for client_state in client_states:
            if _testing:
                print('Updating state for client {0} given new consensus.'.\
                    format(client_state['id']))
                    
            # Update guard list
            # Tor does this stuff whenever a descriptor is obtained        
            guards = client_state['guards']                
            for guard, guard_props in guards.items():
                # set guard as down if (following Tor's
                # entry_guard_set_status)
                # - not in current nodelist (!node check)
                #   - note that a node can appear the nodelist but not
                #     in consensus if it has an existing descriptor
                #     in routerlist (unclear to me when this gets purged)
                # - Running flag not set
                #   - note that all nodes not in current consensus get
                #     *all* their node flags set to zero
                # - Guard flag not set [and not a bridge])
                # note that hibernating *not* considered here
                if (guard_props['bad_since'] == None):
                    if (guard not in cons_rel_stats) or\
                        (stem.Flag.RUNNING not in\
                         cons_rel_stats[guard].flags) or\
                        (stem.Flag.GUARD not in\
                         cons_rel_stats[guard].flags):
                        if _testing:
                            print('Putting down guard {0}'.format(guard))
                        guard_props['bad_since'] = cons_valid_after
                else:
                    if (guard in cons_rel_stats) and\
                        (stem.Flag.RUNNING not in\
                         cons_rel_stats[guard].flags) and\
                        (stem.Flag.GUARD not in\
                         cons_rel_stats[guard].flags):
                        if _testing:
                            print('Bringing up guard {0}'.format(guard))
                        guard_props['bad_since'] = None
                # remove if down time including this period exceeds limit
                if (guard_props['bad_since'] != None):
                    if (cons_fresh_until-guard_props['bad_since'] >=\
                        guard_down_time):
                        if _testing:
                            print('Guard down too long, removing: {0}'.\
                                format(guard))
                        del guards[guard]
                # expire old guards
                if (guard_props['expires'] <= cons_valid_after):
                    if _testing:
                        print('Expiring guard: {0}'.format(guard))
                    del guards[guard]
            
            # Kill circuits using relays that now appear to be "down", where
            #  down is not in consensus or without Running flag.            
            kill_circuits_by_relay(client_state, \
                lambda r: (r not in cons_rel_stats) or \
                    (stem.Flag.RUNNING not in cons_rel_stats[r].flags), \
                _testing)
                              
        # filter exits for port needs and compute their weights
        # do this here to avoid repeating per client
        port_need_weighted_exits = {}
        for port, need in port_needs_global.items():
            port_need_exits = filter_exits(cons_rel_stats, descriptors,\
                need['fast'], need['stable'], False, None, port)
            if _testing:
                print('# exits for port {0}: {1}'.\
                    format(port, len(port_need_exits)))
            port_need_exit_weights = get_position_weights(\
                port_need_exits, cons_rel_stats, 'e', cons_bw_weights,\
                cons_bwweightscale)
            port_need_weighted_exits[port] =\
                get_weighted_nodes(port_need_exits, port_need_exit_weights)

        # filter middles and precompute cumulative weights
        potential_middles = filter(lambda x: middle_filter(x, cons_rel_stats,\
            descriptors, None, None, None, None), cons_rel_stats.keys())
        if _testing:
            print('# potential middles: {0}'.format(len(potential_middles)))                
        potential_middle_weights = get_position_weights(potential_middles,\
            cons_rel_stats, 'm', cons_bw_weights, cons_bwweightscale)
        weighted_middles = get_weighted_nodes(potential_middles,\
            potential_middle_weights)
            
        # filter guards and precompute cumulative weights
        # New guards are selected infrequently after the experiment start
        # so doing this here instead of on-demand per client may actually
        # slow things down. We do it to improve scalability with sample number.
        potential_guards = filter_guards(cons_rel_stats, descriptors)
        if _testing:
            print('# potential guards: {0}'.format(len(potential_guards)))        
        potential_guard_weights = get_position_weights(potential_guards,\
            cons_rel_stats, 'g', cons_bw_weights, cons_bwweightscale)
        weighted_guards = get_weighted_nodes(potential_guards,\
            potential_guard_weights)    
       
        # for simplicity, step through time one minute at a time
        time_step = 60
        cur_time = cur_period_start
        while (cur_time < cur_period_end):    
            # expire port needs
            for port, need in port_needs_global.items():
                if (need['expires'] != None) and\
                    (need['expires'] <= cur_time):
                    del port_needs_global[port]
                    for client_state in client_states:
                        del client_state['port_needs_covered'][port]
                        
            # update hibernating status
            while (hibernating_statuses) and\
                (hibernating_statuses[-1][0] <= cur_time):
                hibernating_change = hibernating_statuses.pop()
                hibernating_status[hibernating_change[1]] = \
                    hibernating_change[2]
            
            # do timed client updates
            for client_state in client_states:
                timed_client_updates(cur_time, client_state,\
                    num_guards, min_num_guards, guard_expiration_min,\
                    guard_expiration_max, max_circuit_dirtiness,\
                    circuit_idle_timeout, max_unused_open_circuits,\
                    port_needs_global, cons_rel_stats,\
                    cons_valid_after, cons_fresh_until, cons_bw_weights,\
                    cons_bwweightscale, descriptors, hibernating_status,\
                    port_need_weighted_exits, weighted_middles,\
                    weighted_guards, _testing)
                    
            # TMP
            for client_state in client_states:
                print('Client {0} circuits:'.format(client_state['id']))
                print('len(client_state[\'dirty_exit_circuits\']): {0}'.\
                    format(len(client_state['dirty_exit_circuits'])))
                print('len(client_state[\'clean_exit_circuits\']): {0}'.\
                    format(len(client_state['clean_exit_circuits'])))

            # collect streams that occur during current period
            while (stream_start < len(streams)) and\
                (streams[stream_start]['time'] < cur_time):
                stream_start += 1
            stream_end = stream_start
            while (stream_end < len(streams)) and\
                (streams[stream_end]['time'] < cur_time + time_step):
                stream_end += 1                                              
                
            # assign streams in this minute to circuits
            for stream_idx in range(stream_start, stream_end):
                stream = streams[stream_idx]
                
                # add need/extend expiration for ports in streams
                if (stream['type'] == 'resolve'):
                    # as in Tor, treat RESOLVE requests as port 80 for
                    #  prediction (see rep_hist_note_used_resolve())
                    port = 80
                else:
                    port = stream['port']
                if (port in port_needs_global):
                    if (port_needs_global[port]['expires'] != None) and\
                        (port_needs_global[port]['expires'] <\
                            stream['time'] + port_need_lifetime):
                        port_needs_global[port]['expires'] =\
                            stream['time'] + port_need_lifetime
                else:
                    port_needs_global[port] = {
                        'expires':(stream['time']+port_need_lifetime),
                        'fast':True,
                        'stable':(port in long_lived_ports),
                        'cover_num':port_need_cover_num}
                    # adjust cover counts for the new port need
                    for client_state in client_states:
                        client_state['port_needs_covered'][port] = 0
                        for circuit in client_state['clean_exit_circuits']:
                            if (circuit_covers_port_need(circuit,\
                                    descriptors, port,\
                                    port_needs_global[port])):
                                client_state['port_needs_covered'][port]\
                                    += 1
                                circuit['covering'].append(port)
                    # precompute exit list and weights for new port need
                    port_need_exits = filter_exits(cons_rel_stats,\
                        descriptors, port_needs_global[port]['fast'],\
                        port_needs_global[port]['stable'], False,\
                        None, port)
                    if _testing:                            
                        print('# exits for new need at port {0}: {1}'.\
                            format(len(port_need_exits)))
                    port_need_exit_weights = get_position_weights(\
                        port_need_exits, cons_rel_stats, 'e',\
                        cons_bw_weights, cons_bwweightscale)
                    port_need_weighted_exits[port] =\
                        get_weighted_nodes(port_need_exits,\
                            port_need_exit_weights)

                # create weighted exits for this stream
                stream_exits = None
                if (stream['type'] == 'connect'):
                    stable = (stream['port'] in long_lived_ports)
                    stream_exits = filter_exits(cons_rel_stats,\
                        descriptors, True, stable, False, stream['ip'],\
                        stream['port'])                    
                    if _testing:                        
                        print('# exits for stream to {0} on port {1}: {2}'.\
                            format(stream['ip'], stream['port'],
                                len(stream_exits)))
                elif (stream['type'] == 'resolve'):
                    stream_exits = filter_exits(cons_rel_stats,\
                        descriptors, True, False, False, None, None)                    
                    if _testing:                        
                        print('# exits for RESOLVE stream: {0}'.\
                            format(len(stream_exits)))
                else:
                    raise ValueError('ERROR: Unrecognized stream type: {0}'.\
                        format(stream['type']))
                stream_exit_weights = get_position_weights(\
                    stream_exits, cons_rel_stats, 'e', cons_bw_weights,\
                    cons_bwweightscale)
                stream_weighted_exits = get_weighted_nodes(\
                    stream_exits, stream_exit_weights)                
                
                # do client stream assignment
                for client_state in client_states:
                    if _testing:                
                        print('Client {0} stream assignment.'.\
                            format(client_state['id']))
                    guards = client_state['guards']
                 
                    stream_assigned = client_assign_stream(\
                        client_state, stream, cons_rel_stats,\
                        cons_valid_after, cons_fresh_until,\
                        cons_bw_weights, cons_bwweightscale,\
                        descriptors, hibernating_status, num_guards,\
                        min_num_guards, guard_expiration_min,\
                        guard_expiration_max, stream_weighted_exits,\
                        weighted_middles, weighted_guards, long_lived_ports,\
                        _testing)
                    if (not _testing):
                        print_mapped_stream(client_state['id'],\
                            stream_assigned, stream, descriptors)
            
            cur_time += time_step
    
    
if __name__ == '__main__':
    command = None
    usage = 'Usage: pathsim.py [command]\nCommands:\n\
\tprocess [start_year] [start_month] [end_year] [end_month] [in_dir] [out_dir]:\
 match relays in each consensus in in_dir/consensuses-year-month with \
descriptors in in_dir/server-descriptors-year-month, where year and month \
range from start_year and start_month to end_year and end_month. Write the \
matched descriptors for each consensus to \
out_dir/processed_descriptors-year-month.\n\
\tsimulate \
[descriptors] [# samples] [# reqs] [testing]: Do a\
 bunch of simulated path selections using consensuses from \
[consensuses], matching descriptors from [descriptors], taking \
[# samples], making [# reqs] web requests per hour, and printing debug info if [testing].'
    if (len(sys.argv) <= 1):
        print(usage)
        sys.exit(1)
        
    command = sys.argv[1]
    if (command != 'process') and (command != 'simulate'):
        print(usage)
    elif (command == 'process'):
        if (len(sys.argv) < 8):
            print(usage)
            sys.exit(1)
        start_year = int(sys.argv[2])
        start_month = int(sys.argv[3])
        end_year = int(sys.argv[4])
        end_month = int(sys.argv[5])
        in_dir = sys.argv[6]
        out_dir = sys.argv[7]

        in_dirs = []
        month = start_month
        for year in range(start_year, end_year+1):
            while ((year < end_year) and (month <= 12)) or \
                (month <= end_month):
                if (month <= 9):
                    prepend = '0'
                else:
                    prepend = ''
                cons_dir = os.path.join(in_dir, 'consensuses-{0}-{1}{2}'.\
                    format(year, prepend, month))
                desc_dir = os.path.join(in_dir, \
                    'server-descriptors-{0}-{1}{2}'.\
                    format(year, prepend, month))
                desc_out_dir = os.path.join(out_dir, \
                    'network-state-{0}-{1}{2}'.\
                    format(year, prepend, month))
                if (not os.path.exists(desc_out_dir)):
                    os.mkdir(desc_out_dir)
                in_dirs.append((cons_dir, desc_dir, desc_out_dir))
                month += 1
            month = 1
        process_consensuses(in_dirs)
    elif (command == 'simulate'):
        # get lists of consensuses and the related processed-descriptor files 
        if (len(sys.argv) >= 3):
            descriptor_dir = sys.argv[2]
        else:
            descriptor_dir = 'out/processed-descriptors'
        if (len(sys.argv) >= 4):
            num_samples = int(sys.argv[3])
        else:
            num_samples = 1
        if (len(sys.argv) >= 5):
            num_requests = int(sys.argv[4])
        else:
            num_requests = 6
        if (len(sys.argv) >= 6) and (sys.argv[5] == '1'):
            _testing = True
        else:
            _testing = False            
        
        """Replaced consensus/descriptor files with pickled network state.
        consensus_files = []
        for dirpath, dirnames, filenames in os.walk(consensuses_dir,\
            followlinks=True):
            for filename in filenames:
                if (filename[0] != '.'):
                    consensus_files.append(os.path.join(dirpath,filename))
        consensus_files.sort()
        
        processed_descriptor_files = []
        for dirpath, dirnames, filenames in os.walk(descriptor_dir,\
            followlinks=True):
            for filename in filenames:
                if (filename[0] != '.'):
                    processed_descriptor_files.append(\
                        os.path.join(dirpath,filename))
        processed_descriptor_files.sort()
        """
        
        network_state_files = []
        for dirpath, dirnames, filenames in os.walk(descriptor_dir,\
            followlinks=True):
            for filename in filenames:
                if (filename[0] != '.'):
                    network_state_files.append(os.path.join(dirpath,filename))
        network_state_files.sort()

        # determine start and end times
        """Replaced with network state files.
        start_time = None
        with open(consensus_files[0]) as cf:
            for rel_stat in sd.parse_file(cf, validate=False):
                if (start_time == None):
                    start_time =\
                        timestamp(rel_stat.document.valid_after)
                    break
        end_time = None
        with open(consensus_files[-1]) as cf:
            for rel_stat in sd.parse_file(cf, validate=False):
                if (end_time == None):
                    end_time =\
                        timestamp(rel_stat.document.fresh_until)
                    break
        """
        start_time = None
        with open(network_state_files[0]) as nsf:
            consensus = pickle.load(nsf)
            start_time = timestamp(consensus.valid_after)
        end_time = None
        with open(network_state_files[-1]) as nsf:
            consensus = pickle.load(nsf)
            end_time = timestamp(consensus.fresh_until)

        # simple user that makes a port 80 request /resolve every x / y seconds
        http_request_wait = int(60 / num_requests) * 60
        str_ip = '74.125.131.105' # www.google.com
        t = start_time
        streams = []
        while (t < end_time):
            streams.append({'time':t,'type':'connect','ip':str_ip,'port':80})
            t += http_request_wait
# Replaced call arguments with network_state_files
#        create_circuits(consensus_files, processed_descriptor_files, streams,\
#            num_samples)    
        create_circuits(network_state_files, streams, num_samples)                

# TODO
# - support IPv6 addresses
# - We do not consider removing stable/fast requirements if a suitable relay can't be found at some point. Tor does this. Rather, we just error.
# - Instead of immediately using a new consensus, set a random time to
#   switch to the new one, following the process in dir-spec.txt (Sec. 5.1).
# - Do something intelligent with empty node sets rather than just raise error.
# - circuits only recorded as fast/stable/internal if they were chosen to
#   satisfy that, but they may just by chance. should we check?
# - Tor actually seems to build a circuit to cover a port by randomly selecting from exits that cover *some* unhandled port (see choose_good_exit_server_general() in circuitbuild.c). Possibly change procedure for covering ports to act like this.
# - We should expire descriptors older than router_max_age on a per-minute basis. I'm not sure exactly how relays in the consensus but without descriptors are treated, especially in terms of putting guards down. As an approximation, we expire descriptors while building consensuses, and thus do so at most an hour off from when a running relay would. Given that router_max_age is 48 hours, that not large relative error for how long a relay may be used. Also, I don't think that in the Tor metrics data a relay ever appears in the consensus but does not have a recent descriptor.


##### Relevant lines for path selection extracted from Tor specs.

# Circuit creation according to path-spec.txt
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

# Path selection according to dir-spec.txt
# 1. Clients SHOULD NOT use non-'Valid' or non-'Running' routers
# 2. Clients SHOULD NOT use non-'Fast' routers for any purpose other than
#    very-low-bandwidth circuits (such as introduction circuits).
# 3. Clients SHOULD NOT use non-'Stable' routers for circuits that are
#    likely to need to be open for a very long time
# 4. Clients SHOULD NOT choose non-'Guard' nodes when picking entry guard
# 5. if the [Hibernate] value is 1, then the Tor relay was hibernating when
#    the descriptor was published, and shouldn't be used to build circuits."    

# Path selection according to path-spec.txt
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
