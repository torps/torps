import datetime
import os
import os.path
from stem import Flag
from stem.exit_policy import ExitPolicy
from random import random, randint, choice
import sys
import collections
import cPickle as pickle
import argparse
from models import *
import congestion_aware_pathsim
#import vcs_pathsim
import process_consensuses
import re

_testing = False#True

class RouterStatusEntry:
    """
    Represents a relay entry in a consensus document.
    Slim version of stem.descriptor.router_status_entry.RouterStatusEntry.
    """
    def __init__(self, fingerprint, nickname, flags, bandwidth):
        self.fingerprint = fingerprint
        self.nickname = nickname
        self.flags = flags
        self.bandwidth = bandwidth
    

class NetworkStatusDocument:
    """
    Represents a consensus document.
    Slim version of stem.descriptor.networkstatus.NetworkStatusDocument.
    """
    def __init__(self, valid_after, fresh_until, bandwidth_weights, \
        bwweightscale, relays):
        self.valid_after = valid_after
        self.fresh_until = fresh_until
        self.bandwidth_weights = bandwidth_weights
        self.bwweightscale = bwweightscale
        self.relays = relays


class ServerDescriptor:
    """
    Represents a server descriptor.
    Slim version of stem.descriptor.server_descriptor.ServerDescriptor combined
    with stem.descriptor.server_descriptor.RelayDescriptor.
    """
    def __init__(self, fingerprint, hibernating, nickname, family, address,
        exit_policy, ntor_onion_key):
        self.fingerprint = fingerprint
        self.hibernating = hibernating
        self.nickname = nickname
        self.family = family
        self.address = address
        self.exit_policy = exit_policy
        self.ntor_onion_key = ntor_onion_key

class TorOptions:
    """Stores parameters set by Tor."""
    # given by #define ROUTER_MAX_AGE (60*60*48) in or.h    
    router_max_age = 60*60*48    
    
    num_guards = 3
    min_num_guards = 2
    guard_expiration_min = 60*24*3600 # min time until guard removed from list
    guard_expiration_max = 90*24*3600 # max time until guard removed from list 
    default_bwweightscale = 10000   
    
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
    # including 6523, which was added in 0.2.4.12-alpha
    long_lived_ports = [21, 22, 706, 1863, 5050, 5190, 5222, 5223, 6523, 6667,
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
    
    # number of times to attempt to find circuit with at least one NTor hop
    # from #define MAX_POPULATE_ATTEMPTS 32 in circuicbuild.c
    max_populate_attempts = 32
    

def timestamp(t):
    """Returns UNIX timestamp"""
    td = t - datetime.datetime(1970, 1, 1)
    ts = td.days*24*60*60 + td.seconds
    return ts


def pad_network_state_files(network_state_files):
    """Add hour-long gaps into files list where gaps exist in file times."""
    nsf_date = None
    network_state_files_padded = []
    for nsf in network_state_files:
        f_datenums = map(int, os.path.basename(nsf).split('-')[:-1])
        new_nsf_date = datetime.datetime(f_datenums[0], f_datenums[1], f_datenums[2], f_datenums[3], f_datenums[4], f_datenums[5])
        if (nsf_date != None):
            td = new_nsf_date - nsf_date
            if (int(td.total_seconds()) != 3600):
                if (int(td.total_seconds()) % 3600 != 0):
                    raise ValueError('Gap between {0} and {1} not some number of hours.'.format(nsf_date, new_nsf_date))
                if _testing:
                    print('Missing consensuses between {0} and {1}'.\
                        format(nsf_date, new_nsf_date))
                num_missing_hours = int(td.total_seconds()/3600) - 1
                for i in range(num_missing_hours):
                    network_state_files_padded.append(None)
                network_state_files_padded.append(nsf)
            else:
                network_state_files_padded.append(nsf)
        else:
            network_state_files_padded.append(nsf)
        nsf_date = new_nsf_date                                    
    return network_state_files_padded


def get_bw_weight(flags, position, bw_weights):
    """Returns weight to apply to relay's bandwidth for given position.
        flags: list of Flag values for relay from a consensus
        position: position for which to find selection weight,
             one of 'g' for guard, 'm' for middle, and 'e' for exit
        bw_weights: bandwidth_weights from NetworkStatusDocumentV3 consensus
    """
    
    if (position == 'g'):
        if (Flag.GUARD in flags) and (Flag.EXIT in flags):
            return bw_weights['Wgd']
        elif (Flag.GUARD in flags):
            return bw_weights['Wgg']
        elif (Flag.EXIT not in flags):
            return bw_weights['Wgm']
        else:
            raise ValueError('Wge weight does not exist.')
    elif (position == 'm'):
        if (Flag.GUARD in flags) and (Flag.EXIT in flags):
            return bw_weights['Wmd']
        elif (Flag.GUARD in flags):
            return bw_weights['Wmg']
        elif (Flag.EXIT in flags):
            return bw_weights['Wme']
        else:
            return bw_weights['Wmm']
    elif (position == 'e'):
        if (Flag.GUARD in flags) and (Flag.EXIT in flags):
            return bw_weights['Wed']
        elif (Flag.GUARD in flags):
            return bw_weights['Weg']
        elif (Flag.EXIT in flags):
            return bw_weights['Wee']
        else:
            return bw_weights['Wem']    
    else:
        raise ValueError('get_weight does not support position {0}.'.format(
            position))

            
def select_weighted_node(weighted_nodes):
    """Takes (node,cum_weight) pairs where non-negative cum_weight increases,
    ending at 1. Use cum_weights as cumulative probablity to select a node."""
    r = random()
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


def might_exit_to_port(descriptor, port):
    """Returns if will exit to port for *some* ip.
    Is conservative - never returns a false negative."""
    for rule in descriptor.exit_policy:
        if (port >= rule.min_port) and\
                (port <= rule.max_port): # assumes full range for wildcard port
            if rule.is_accept:
                return True
            else:
                if (rule.is_address_wildcard()) or\
                    (rule.get_masked_bits() == 0):
                    return False
    return True # default accept if no rule matches


def can_exit_to_port(descriptor, port):
    """Derived from compare_unknown_tor_addr_to_addr_policy() in policies.c.
    That function returns ACCEPT, PROBABLY_ACCEPT, REJECT, and PROBABLY_REJECT.
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
        

def exit_filter(exit, cons_rel_stats, descriptors, fast, stable, internal, ip,\
    port, loose):
    """Applies the criteria for choosing a relay as an exit.
    If internal, doesn't consider exit policy.
    If IP and port given, simply applies exit policy.
    If just port given, guess as Tor does, with the option to be slightly more
    loose than Tor and avoid false negatives (via loose=True).
    If IP and port not given, check policy for any allowed exiting. This
    behavior is for SOCKS RESOLVE requests in particular."""
    rel_stat = cons_rel_stats[exit]
    desc = descriptors[exit]
    if (Flag.BADEXIT not in rel_stat.flags) and\
        (Flag.RUNNING in rel_stat.flags) and\
        (Flag.VALID in rel_stat.flags) and\
        ((not fast) or (Flag.FAST in rel_stat.flags)) and\
        ((not stable) or (Flag.STABLE in rel_stat.flags)):
        if (internal):
            # In an "internal" circuit final node is chosen just like a
            # middle node (ignoring its exit policy).
            return True
        elif (ip != None):
            return desc.exit_policy.can_exit_to(ip, port)
        elif (port != None):
            if (not loose):
                return can_exit_to_port(desc, port)
            else:
                return might_exit_to_port(desc, port)
        else:
            return (not policy_is_reject_star(desc.exit_policy))


def filter_exits(cons_rel_stats, descriptors, fast, stable, internal, ip,\
    port):
    """Applies exit filter to relays."""
    exits = []
    for fprint in cons_rel_stats:
        if exit_filter(fprint, cons_rel_stats, descriptors, fast, stable,\
            internal, ip, port, False):
                exits.append(fprint)
    return exits
    

def filter_exits_loose(cons_rel_stats, descriptors, fast, stable, internal,\
    ip, port):
    """Applies loose exit filter to relays."""    
    exits = []
    for fprint in cons_rel_stats:
        if exit_filter(fprint, cons_rel_stats, descriptors, fast, stable,\
            internal, ip, port, True):
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

    
def in_same_family(descriptors, node1, node2):
    """Takes list of descriptors and two node fingerprints,
    checks if nodes list each other as in the same family."""

    desc1 = descriptors[node1]
    desc2 = descriptors[node2]
    fprint1 = desc1.fingerprint
    fprint2 = desc2.fingerprint
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
    return (Flag.RUNNING in rel_stat.flags) and\
            ((fast==None) or (not fast) or\
                (Flag.FAST in rel_stat.flags)) and\
            ((stable==None) or (not stable) or\
                (Flag.STABLE in rel_stat.flags)) and\
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
            return ((not fast) or (Flag.FAST in rel_stat.flags)) and\
                ((not stable) or (Flag.STABLE in rel_stat.flags)) and\
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
        if (Flag.RUNNING in rel_stat.flags) and\
            (Flag.VALID in rel_stat.flags) and\
            (Flag.GUARD in rel_stat.flags) and\
            (fprint in descriptors):
            guards.append(fprint)   
    
    return guards
    

def get_new_guard(bw_weights, bwweightscale, cons_rel_stats, descriptors,\
    client_guards, weighted_guards=None):
    """Selects a new guard that doesn't conflict with the existing list."""
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
    descriptors, fast, stable, guards,\
    exit,\
    circ_time, weighted_guards=None):
    """Obtains needed number of live guards that will work for circuit.
    Chooses new guards if needed, and *modifies* guard list by adding them."""
    # Get live guards then add new ones until TorOptions.num_guards reached,
    # where live is
    #  - bad_since isn't set
    #  - unreachable_since isn't set without retry
    #  - has descriptor, though create_circuits should ensure descriptor exists
    # Note that node need not have Valid flag to be live. As far as I can tell,
    # a Valid flag is needed to be added to the guard list, but isn't needed 
    # after that point.
    # Note that hibernating status is not an input here.
    # Rules derived from Tor source: choose_random_entry_impl() in entrynodes.c
    
    # add guards if not enough in list
    if (len(guards) < TorOptions.num_guards):
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
        for i in range(TorOptions.num_guards - len(live_guards)):
            new_guard = get_new_guard(bw_weights, bwweightscale,\
                cons_rel_stats, descriptors, guards,\
                weighted_guards)
            if _testing:                
                print('Need guard. Adding {0} [{1}]'.format(\
                    cons_rel_stats[new_guard].nickname, new_guard))
            expiration = randint(TorOptions.guard_expiration_min,\
                TorOptions.guard_expiration_max)
            guards[new_guard] = {'expires':(expiration+\
                circ_time), 'bad_since':None, 'unreachable_since':None,\
                'last_attempted':0, 'made_contact':False}

    # check for guards that will work for this circuit
    guards_for_circ = filter(lambda x: guard_filter_for_circ(x,\
        cons_rel_stats, descriptors, fast, stable, exit, circ_time, guards),\
        guards)
    # add new guards while there aren't enough for this circuit
    # adding is done without reference to the circuit - how Tor does it
    while (len(guards_for_circ) < TorOptions.min_num_guards):
            new_guard = get_new_guard(bw_weights, bwweightscale,\
                cons_rel_stats, descriptors, guards,\
                weighted_guards)
            if _testing:                
                print('Need guard for circuit. Adding {0} [{1}]'.format(\
                    cons_rel_stats[new_guard].nickname, new_guard))
            expiration = randint(TorOptions.guard_expiration_min,\
                TorOptions.guard_expiration_max)
            guards[new_guard] = {'expires':(expiration+\
                circ_time), 'bad_since':None, 'unreachable_since':None,\
                'last_attempted':0, 'made_contact':False}
            if (guard_filter_for_circ(new_guard, cons_rel_stats, descriptors,\
                fast, stable, exit, circ_time, guards)):
                guards_for_circ.append(new_guard)

    # return first TorOptions.num_guards usable guards
    return guards_for_circ[0:TorOptions.num_guards]


def circuit_covers_port_need(circuit, descriptors, port, need):
    """Returns if circuit satisfies a port need, ignoring the circuit
    time and need expiration."""
    return ((not need['fast']) or (circuit['fast'])) and\
            ((not need['stable']) or (circuit['stable'])) and\
            (can_exit_to_port(descriptors[circuit['path'][-1]], port))


def print_mapped_streams_header(format, file=sys.stdout):
    """Prints log header for stream lines."""
    if (format == 'relay-adv'):
        file.write('Sample\tTimestamp\tCompromise Code\n')
    elif (format == 'network-adv'):
        file.write('Sample\tTimestamp\tGuard ip\tExit IP\tDestination IP\n')
    else:
        file.write('Sample\tTimestamp\tGuard IP\tMiddle IP\tExit IP\tDestination IP\n')

        
def print_mapped_stream(client_id, circuit, stream, descriptors, format,
    file=sys.stdout):
    """Writes log line to file (default stdout) showing client, time, IPs, and
    fingerprints in path of stream."""
    
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
    if (format == 'relay-adv'):
        guard_prefix = '000000000000000000000000000000' # as in add_adv_guards
        exit_prefix = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' # as in add_adv_exits
        guard_bad = False
        exit_bad = False
        if (circuit['path'][0][0:30] == guard_prefix) or\
            (circuit['path'][0][0:30] == exit_prefix):
            guard_bad = True
        if (circuit['path'][2][0:30] == guard_prefix) or\
            (circuit['path'][2][0:30] == exit_prefix):
            exit_bad = True
        compromise_code = 0
        if (guard_bad and exit_bad):
            compromise_code = 3
        elif guard_bad:
            compromise_code = 1
        elif exit_bad:
            compromise_code = 2
        file.write('{0}\t{1}\t{2}\n'.format(client_id, stream['time'],
            compromise_code))
    elif (format == 'network-adv'):
        file.write('{0}\t{1}\t{2}\t{3}\t{4}\n'.format(client_id, stream['time'],
            guard_ip, exit_ip, dest_ip))
    else:
        file.write('{0}\t{1}\t{2}\t{3}\t{4}\t{5}\n'.format(client_id,
            stream['time'], guard_ip, middle_ip, exit_ip, dest_ip))


def circuit_supports_stream(circuit, stream, descriptors):
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
                (stream['port'] not in TorOptions.long_lived_ports)):
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

        
def uncover_circuit_ports(circuit, port_needs_covered):
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
    
    
def kill_circuits_by_relay(client_state, relay_down_fn, msg):
    """Kill circuits with a relay that is down as judged by relay_down_fn."""    
    # go through dirty circuits
    new_dirty_exit_circuits = collections.deque()
    while(len(client_state['dirty_exit_circuits']) > 0):
        circuit = client_state['dirty_exit_circuits'].popleft()
        rel_down = None
        for i in range(len(circuit['path'])):
            relay = circuit['path'][i]
            if relay_down_fn(relay):
                rel_down = relay
                break
        if (rel_down == None):
            new_dirty_exit_circuits.append(circuit)
        else:
            if (_testing):
                print('Killing dirty circuit because {0} {1}.'.\
                    format(rel_down, msg))
    client_state['dirty_exit_circuits'] = new_dirty_exit_circuits
    # go through clean circuits
    new_clean_exit_circuits = collections.deque()
    while(len(client_state['clean_exit_circuits']) > 0):
        circuit = client_state['clean_exit_circuits'].popleft()
        rel_down = None
        for i in range(len(circuit['path'])):
            relay = circuit['path'][i]
            if relay_down_fn(relay):
                rel_down = relay
                break
        if (rel_down == None):
            new_clean_exit_circuits.append(circuit)
        else:
            if (_testing):
                print('Killing clean circuit because {0} {1}.'.\
                    format(rel_down, msg))
            uncover_circuit_ports(circuit, client_state['port_needs_covered'])
    client_state['clean_exit_circuits'] = new_clean_exit_circuits


def get_network_state(ns_file, add_time, add_relays):
    """Reads in network state file and added relays, returns needed values."""
    if _testing:
        print('Using file {0}'.format(ns_file))

    cons_rel_stats = {}
    with open(ns_file, 'r') as nsf:
        consensus = pickle.load(nsf)
        new_descriptors = pickle.load(nsf)
        hibernating_statuses = pickle.load(nsf)
        
    # set variables from consensus
    cons_valid_after = timestamp(consensus.valid_after)            
    cons_fresh_until = timestamp(consensus.fresh_until)
    cons_bw_weights = consensus.bandwidth_weights
    if (consensus.bwweightscale == None):
        cons_bwweightscale = TorOptions.default_bwweightscale
    else:
        cons_bwweightscale = consensus.bwweightscale
    for relay in consensus.relays:
        if (relay in new_descriptors):
            cons_rel_stats[relay] = consensus.relays[relay]
            
    if (add_time <= cons_valid_after):
        # include additional relays in consensus
        if _testing:
            print('Adding {0} relays to consensus.'.format(\
                len(add_relays)))
        for fprint, relay in add_relays.items():
            if fprint in cons_rel_stats:
                raise ValueError(\
                    'Added relay exists in consensus: {0}:{1}'.\
                        format(relay.nickname, fprint))
            cons_rel_stats[fprint] = relay
        # include hibernating statuses for added relays
        hibernating_statuses.extend([(0, fp, False) \
            for fp in add_relays])
    
    return (cons_valid_after, cons_fresh_until, cons_bw_weights,
        cons_bwweightscale, cons_rel_stats, hibernating_statuses,
        new_descriptors)
        
        
def set_initial_hibernating_status(hibernating_status, hibernating_statuses,
    cur_period_start, cons_rel_stats):
    """Reads hibernating statuses and updates initial relay status."""
    while (hibernating_statuses) and\
        (hibernating_statuses[-1][0] <= cur_period_start):
        hs = hibernating_statuses.pop()
        if (hs[1] in hibernating_status) and _testing:
            print('Reset hibernating of {0}:{1} to {2}.'.format(\
                cons_rel_stats[hs[1]].nickname, hibernating_status[hs[1]],
                    hs[2]))
        hibernating_status[hs[1]] = hs[2]
        if _testing:
            if (hs[2]):
                print('{0} was hibernating at start of consensus period.'.\
                    format(cons_rel_stats[hs[1]].nickname))        
                                

def period_client_update(client_state, cons_rel_stats, cons_fresh_until,\
    cons_valid_after):
    """Updates client state for new consensus period."""
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
                (Flag.RUNNING not in\
                 cons_rel_stats[guard].flags) or\
                (Flag.GUARD not in\
                 cons_rel_stats[guard].flags):
                if _testing:
                    print('Putting down guard {0}'.format(guard))
                guard_props['bad_since'] = cons_valid_after
        else:
            if (guard in cons_rel_stats) and\
                (Flag.RUNNING in\
                 cons_rel_stats[guard].flags) and\
                (Flag.GUARD in\
                 cons_rel_stats[guard].flags):
                if _testing:
                    print('Bringing up guard {0}'.format(guard))
                guard_props['bad_since'] = None
        # remove if down time including this period exceeds limit
        if (guard_props['bad_since'] != None):
            if (cons_fresh_until-guard_props['bad_since'] >=\
                TorOptions.guard_down_time):
                if _testing:
                    print('Guard down too long, removing: {0}'.\
                        format(guard))
                del guards[guard]
                continue
        # expire old guards
        if (guard_props['expires'] <= cons_valid_after):
            if _testing:
                print('Expiring guard: {0}'.format(guard))
            del guards[guard]
    
    # Kill circuits using relays that now appear to be "down", where
    #  down is not in consensus or without Running flag.            
    kill_circuits_by_relay(client_state, \
        lambda r: (r not in cons_rel_stats) or \
            (Flag.RUNNING not in cons_rel_stats[r].flags),\
            'is down')
            
            
def timed_updates(cur_time, port_needs_global, client_states,
    hibernating_statuses, hibernating_status, cons_rel_stats):
    """Perform timing-based updates that apply to all clients."""            
    # expire port needs
    for port, need in port_needs_global.items():
        if (need['expires'] != None) and\
            (need['expires'] <= cur_time):
            if _testing:
                print('Port need for {0} expiring.'.format(port))
            del port_needs_global[port]
            for client_state in client_states:
                del client_state['port_needs_covered'][port]
                
    # update hibernating status
    while (hibernating_statuses) and\
        (hibernating_statuses[-1][0] <= cur_time):
        hs = hibernating_statuses.pop()
        if _testing:
            if (hs[1] in cons_rel_stats):
                if hs[2]:
                    print('{0}:{1} started hibernating.'.\
                        format(cons_rel_stats[hs[1]].nickname, hs[1]))
                else:
                    print('{0}:{1} stopped hibernating.'.\
                        format(cons_rel_stats[hs[1]].nickname, hs[1]))
            
        hibernating_status[hs[1]] = hs[2]
            

def timed_client_updates(cur_time, client_state,\
    port_needs_global,\
    cons_rel_stats, cons_valid_after,\
    cons_fresh_until, cons_bw_weights, cons_bwweightscale, descriptors,\
    hibernating_status, port_need_weighted_exits, weighted_middles,\
    weighted_guards, congmodel, pdelmodel):
    """Performs updates to client state that occur on a time schedule."""
    
    guards = client_state['guards']
            
    # kill old dirty circuits
    while (len(client_state['dirty_exit_circuits'])>0) and\
            (client_state['dirty_exit_circuits'][-1]['dirty_time'] <=\
                cur_time - TorOptions.max_circuit_dirtiness):
        if _testing:
            print('Killed dirty exit circuit at time {0} w/ dirty time \
{1}'.format(cur_time, client_state['dirty_exit_circuits'][-1]['dirty_time']))
        client_state['dirty_exit_circuits'].pop()
        
    # kill old clean circuits
    while (len(client_state['clean_exit_circuits'])>0) and\
            (client_state['clean_exit_circuits'][-1]['time'] <=\
                cur_time - TorOptions.circuit_idle_timeout):
        if _testing:
            print('Killed clean exit circuit at time {0} w/ time \
{1}'.format(cur_time, client_state['clean_exit_circuits'][-1]['time']))
        uncover_circuit_ports(client_state['clean_exit_circuits'][-1],\
            client_state['port_needs_covered'])
        client_state['clean_exit_circuits'].pop()
        
    # kill circuits with relays that have gone into hibernation
    kill_circuits_by_relay(client_state, \
        lambda r: hibernating_status[r], 'is hibernating')
                  
    # cover uncovered ports while fewer than
    # TorOptions.max_unused_open_circuits clean
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
                    TorOptions.max_unused_open_circuits):
                new_circ = create_circuit(cons_rel_stats,\
                    cons_valid_after, cons_fresh_until,\
                    cons_bw_weights, cons_bwweightscale,\
                    descriptors, hibernating_status, guards, cur_time,\
                    need['fast'], need['stable'], False, None, port,\
                    congmodel, pdelmodel,\
                    port_need_weighted_exits[port],\
                    True, weighted_middles, weighted_guards)
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
                        
                        
def stream_update_port_needs(stream, port_needs_global,
    port_need_weighted_exits, client_states,
    descriptors, cons_rel_stats, cons_bw_weights, cons_bwweightscale):
    """Updates port needs based on input stream.
    If new port, returns updated list of exits filtered for port."""
    if (stream['type'] == 'resolve'):
        # as in Tor, treat RESOLVE requests as port 80 for
        #  prediction (see rep_hist_note_used_resolve())
        port = 80
    else:
        port = stream['port']
    if (port in port_needs_global):
        if (port_needs_global[port]['expires'] != None) and\
            (port_needs_global[port]['expires'] <\
                stream['time'] + TorOptions.port_need_lifetime):
            port_needs_global[port]['expires'] =\
                stream['time'] + TorOptions.port_need_lifetime
        return None
    else:
        port_needs_global[port] = {
            'expires':(stream['time']+TorOptions.port_need_lifetime),
            'fast':True,
            'stable':(port in TorOptions.long_lived_ports),
            'cover_num':TorOptions.port_need_cover_num}
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
                format(port, len(port_need_exits)))
        port_need_exit_weights = get_position_weights(\
            port_need_exits, cons_rel_stats, 'e',\
            cons_bw_weights, cons_bwweightscale)
        pn_weighted_exits = \
            get_weighted_nodes(port_need_exits, port_need_exit_weights)
        port_need_weighted_exits[port] = pn_weighted_exits
        
        
def get_stream_port_weighted_exits(stream_port, stream,
    cons_rel_stats, descriptors, cons_bw_weights, cons_bwweightscale): 
    """Returns weighted exit list for port of stream."""
    if (stream['type'] == 'connect'):
        stable = (stream_port in TorOptions.long_lived_ports)
        stream_exits =\
            filter_exits_loose(cons_rel_stats,\
                descriptors, True, stable, False,\
                None, stream_port)
        if _testing:                        
            print('# loose exits for stream on port {0}: {1}'.\
                format(stream_port, len(stream_exits)))
    elif (stream['type'] == 'resolve'):
        stream_exits =\
            filter_exits(cons_rel_stats, descriptors, True,\
                False, False, None, None)                    
        if _testing:                        
            print('# exits for RESOLVE stream: {0}'.\
                format(len(stream_exits)))
    else:
        raise ValueError(\
            'ERROR: Unrecognized stream type: {0}'.\
            format(stream['type']))
    stream_exit_weights = get_position_weights(\
        stream_exits, cons_rel_stats, 'e',\
        cons_bw_weights, cons_bwweightscale)
    stream_weighted_exits = get_weighted_nodes(\
        stream_exits, stream_exit_weights)
    return stream_weighted_exits                               
        
        
def client_assign_stream(client_state, stream, cons_rel_stats,\
    cons_valid_after, cons_fresh_until, cons_bw_weights, cons_bwweightscale,\
    descriptors, hibernating_status,\
    stream_weighted_exits,\
    weighted_middles, weighted_guards, congmodel, pdelmodel):
    """Assigns a stream to a circuit for a given client."""
        
    guards = client_state['guards']
    stream_assigned = None

    # try to use a dirty circuit
    for circuit in client_state['dirty_exit_circuits']:
        if (circuit['dirty_time'] > \
                stream['time'] - TorOptions.max_circuit_dirtiness) and\
            circuit_supports_stream(circuit, stream, descriptors):
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
            if (circuit_supports_stream(circuit, stream, descriptors)):
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
                    client_state['port_needs_covered'])
            else:
                new_clean_exit_circuits.append(circuit)
        client_state['clean_exit_circuits'] =\
            new_clean_exit_circuits
    # if stream still unassigned we must make new circuit
    if (stream_assigned == None):
        new_circ = None
        if (stream['type'] == 'connect'):
            stable = (stream['port'] in TorOptions.long_lived_ports)
            new_circ = create_circuit(cons_rel_stats,\
                cons_valid_after, cons_fresh_until,\
                cons_bw_weights, cons_bwweightscale,\
                descriptors, hibernating_status, guards, stream['time'], True,\
                stable, False, stream['ip'], stream['port'],\
                congmodel, pdelmodel,\
                stream_weighted_exits, False,\
                weighted_middles, weighted_guards)
        elif (stream['type'] == 'resolve'):
            new_circ = create_circuit(cons_rel_stats,\
                cons_valid_after, cons_fresh_until,\
                cons_bw_weights, cons_bwweightscale,\
                descriptors, hibernating_status, guards, stream['time'], True,\
                False, False, None, None,\
                congmodel, pdelmodel,\
                stream_weighted_exits, True,\
                weighted_middles, weighted_guards)
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

    
def select_exit_node(bw_weights, bwweightscale, cons_rel_stats, descriptors,\
    fast, stable, internal, ip, port, weighted_exits=None, exits_exact=False):
    """Chooses a valid exit node. To improve performance when simulating many
    streams, we allow any input weighted_exits list to possibly include
    relays that are invalid for the current circuit (thus we can create
    weighted_exits less often by only considering the port instead of the
    ip/port). Then we randomly select from that list until a suitable exit is
    found.
    """
    if (weighted_exits == None):    
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
        weighted_exits = get_weighted_nodes(exits, weights)      
        exits_exact = True
    
    if (exits_exact):
        return select_weighted_node(weighted_exits)
    else:
        # select randomly until acceptable exit node is found
        i = 1
        while True:
            exit_node = select_weighted_node(weighted_exits)
            if _testing:
                print('select_exit_node() made choice #{0}.'.format(i))
            i += 1
            if (exit_filter(exit_node, cons_rel_stats, descriptors, fast,\
                stable, internal, ip, port, False)):
                return exit_node    


def circuit_supports_ntor(guard_node, middle_node, exit_node, descriptors):
    """Returns True if one node in circuit has ntor key."""
    
    for relay in (guard_node, middle_node, exit_node):
        if (descriptors[relay].ntor_onion_key is not None):
            return True
    return False

def create_circuit(cons_rel_stats, cons_valid_after, cons_fresh_until,\
    cons_bw_weights, cons_bwweightscale, descriptors, hibernating_status,\
    guards, circ_time, circ_fast, circ_stable, circ_internal, circ_ip,\
    circ_port,\
    congmodel, pdelmodel, weighted_exits=None,\
    exits_exact=False, weighted_middles=None, weighted_guards=None):
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
        congmodel: congestion model
        pdelmodel: propagation delay model
        weighted_exits: (list) (middle, cum_weight) pairs for exit position
        exits_exact: (bool) Is weighted_exits exact or does it need rechecking?
            weighed_exits is special because exits are chosen first and thus
            don't depend on the other circuit positions, and so potentially are        
            precomputed exactly.
        weighted_middles: (list) (middle, cum_weight) pairs for middle position
        weighted_guards: (list) (middle, cum_weight) pairs for middle position
    Output:
        circuit: (dict) a newly created circuit with keys
            'time': (int) seconds from time zero
            'fast': (bool) relays must have Fast flag
            'stable': (bool) relays must have Stable flag
            'internal': (bool) is internal (e.g. for hidden service)
            'dirty_time': (int) timestamp of time dirtied, None if clean
            'path': (tuple) list in-order fingerprints for path's nodes
            'covering': (list) ports with needs covered by circuit        
    """
#            'cons_rel_stats': (dict) relay stats for active consensus
    
    if (circ_time < cons_valid_after) or\
        (circ_time >= cons_fresh_until):
        raise ValueError('consensus not fresh for circ_time in create_circuit')
 
    num_attempt = 0
    ntor_supported = False
    while (num_attempt < TorOptions.max_populate_attempts) and\
        (not ntor_supported):
        # select exit node
        i = 1
        while (True):
            exit_node = select_exit_node(cons_bw_weights, cons_bwweightscale,\
                cons_rel_stats, descriptors, circ_fast, circ_stable,\
                circ_internal, circ_ip, circ_port, weighted_exits, exits_exact)
    #        exit_node = select_weighted_node(weighted_exits)
            if (not hibernating_status[exit_node]):
                break
            if _testing:
                print('Exit selection #{0} is hibernating - retrying.'.\
                    format(i))
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
            # get first <= TorOptions.num_guards guards suitable for circuit
            circ_guards = get_guards_for_circ(cons_bw_weights,\
                cons_bwweightscale, cons_rel_stats, descriptors,\
                circ_fast, circ_stable, guards,\
                exit_node,\
                circ_time, weighted_guards)   
            guard_node = choice(circ_guards)
            if (hibernating_status[guard_node]):
                if (not guards[guard_node]['made_contact']):
                    del guards[guard_node]
                    if _testing:
                        print('[Time {0}]: Removed new hibernating guard: {}.'.\
                            format(circ_time,
                                cons_rel_stats[guard_node].nickname))
                elif (guards[guard_node]['unreachable_since'] != None):
                    guards[guard_node]['last_attempted'] = circ_time
                    if _testing:
                        print('[Time {0}]: Guard retried but hibernating: {1}'.\
                            format(circ_time,
                                cons_rel_stats[guard_node].nickname))
                else:
                    guards[guard_node]['unreachable_since'] = circ_time
                    guards[guard_node]['last_attempted'] = circ_time
                    if _testing:
                        print('[Time {0}]: Guard newly hibernating: {1}'.\
                            format(circ_time,
                                cons_rel_stats[guard_node].nickname))
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
            middle_node = select_middle_node(cons_bw_weights,
                cons_bwweightscale, cons_rel_stats, descriptors, circ_fast,
                circ_stable, exit_node, guard_node, weighted_middles)
            if (not hibernating_status[middle_node]):
                break
            if _testing:
                print('Middle selection #{0} is hibernating - retrying.'.\
                    format(i))
            i += 1    
        if _testing:
            print('Middle node: {0} [{1}]'.format(
                cons_rel_stats[middle_node].nickname,
                cons_rel_stats[middle_node].fingerprint))
                
        # ensure one member of the circuit supports the ntor handshake
        ntor_supported = circuit_supports_ntor(guard_node, middle_node,
            exit_node, descriptors)#START
        num_attempt += 1
    if _testing:
        if ntor_supported:
            print('Chose ntor-compatible circuit in {} tries'.\
                format(num_attempt))
        else:
            raise ValueError('ntor-compatible circuit not found in {} tries'.\
                format(num_attempt))
    
    return {'time':circ_time,\
            'fast':circ_fast,\
            'stable':circ_stable,\
            'internal':circ_internal,\
            'dirty_time':None,\
            'path':(guard_node, middle_node, exit_node),\
#            'cons_rel_stats':cons_rel_stats,\
            'covering':[]}
    
def create_circuits(network_state_files, streams, num_samples, add_relays,\
    add_descriptors, add_time, congmodel, pdelmodel, format):
    """Takes streams over time and creates circuits by interaction
    with create_circuit().
      Input:
        network_state_files: list of filenames with network statuses
            as produced by process_consensuses.process_consensuses()
        streams: *ordered* list of streams, where a stream is a dict with keys
            'time': timestamp of when stream request occurs 
            'type': 'connect' for SOCKS CONNECT, 'resolve' for SOCKS RESOLVE
            'ip': IP address of destination
            'port': desired TCP port
        num_samples: (int) # circuit-creation samples to take for given streams
        add_relays: (dict: fprint->RouterStatusEntry)
            add to all existing consensuses (as usual network state just
            continued for missing consensuses)
        add_descriptors: (dict: fprint->ServerDescriptor) add to descriptors
        add_time: (int) timestamp after which specified relays will be added
            to consensuses
        congmodel: (CongestionModel) outputs congestion used by some path algs
        pdelmodel: (PropagationDelayModel) outputs prop delay
        format: (str) 'testing', 'normal', 'relay-adv', or 'network-adv'; sets
            output format
    Output:
        [Prints circuit and guard selections of clients.]
    """
    
    ### Simulation variables ###
    cur_period_start = None
    cur_period_end = None
    stream_start = 0
    stream_end = 0
    init = True

    # store old descriptors (for entry guards that leave consensus)
    # initialize with add_descriptors 
    descriptors = {}
    descriptors.update(add_descriptors)
    
    port_needs_global = {}

    # client states for each sample
    client_states = []
    for i in range(num_samples):
        # guard is dict with client guard state (expiration, bad_since, etc.)
        # port_needs are ports that must be covered by existing circuits        
        # circuit vars are ordered by increasing time since create or dirty
        port_needs_covered = {}
        client_states.append({'id':i,
                            'guards':{},
                            'port_needs_covered':port_needs_covered,
                            'clean_exit_circuits':collections.deque(),
                            'dirty_exit_circuits':collections.deque()})
    ### End simulation variables ###
    
    if (not _testing):
        print_mapped_streams_header(format)

    # run simulation period one pair of consensus/descriptor files at a time
    for ns_file in network_state_files:
        # read in network states            
        if (ns_file != None):
            (cons_valid_after, cons_fresh_until, cons_bw_weights,
            cons_bwweightscale, cons_rel_stats, hibernating_statuses,
            new_descriptors) = get_network_state(ns_file, add_time, add_relays)

            # clear hibernating status to ensure updates come from ns_file
            hibernating_status = {}
                        
            # update descriptors
            descriptors.update(new_descriptors)
        else:
            # gap in consensuses, just advance an hour, keeping network state            
            cons_valid_after += 3600
            cons_fresh_until += 3600
            # set empty statuses, even though previous should have been emptied
            hibernating_statuses = []            
            if _testing:
                print('Filling in consensus gap from {0} to {1}'.\
                format(cons_valid_after, cons_fresh_until))            

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
        set_initial_hibernating_status(hibernating_status,
            hibernating_statuses, cur_period_start, cons_rel_stats)
        
        if (init == True): # first period in simulation
            # seed port need
            port_needs_global[80] = \
                {'expires':(cur_period_start+TorOptions.port_need_lifetime),
                'fast':True, 'stable':False,
                'cover_num':TorOptions.port_need_cover_num}
            for client_state in client_states:
                client_state['port_needs_covered'][80] = 0
            init = False        
        
        # Update client state based on relay status changes in new consensus by
        # updating guard list and killing existing circuits.
        for client_state in client_states:
            period_client_update(client_state, cons_rel_stats,\
                cons_fresh_until, cons_valid_after)

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
                
                
        # Store filtered exits for streams based only on port.
        # Conservative - never excludes a relay that exits to port for some ip.
        # Use port of None to store exits for resolve circuits.
        stream_port_weighted_exits = {}

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
            # do updates that apply to all clients    
            timed_updates(cur_time, port_needs_global, client_states,
                hibernating_statuses, hibernating_status, cons_rel_stats)

            # do timed individual client updates
            for client_state in client_states:
                timed_client_updates(cur_time, client_state,\
                    port_needs_global, cons_rel_stats,\
                    cons_valid_after, cons_fresh_until, cons_bw_weights,\
                    cons_bwweightscale, descriptors, hibernating_status,\
                    port_need_weighted_exits, weighted_middles,\
                    weighted_guards, congmodel, pdelmodel)
                    
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
                stream_update_port_needs(stream, port_needs_global,
                    port_need_weighted_exits, client_states, descriptors,
                    cons_rel_stats, cons_bw_weights, cons_bwweightscale)
                            
                # stream port for purposes of using precomputed exit lists
                if (stream['type'] == 'resolve'):
                    stream_port = None
                else:
                    stream_port = stream['port']
                # create weighted exits for this stream's port
                if (stream_port not in stream_port_weighted_exits):
                    stream_port_weighted_exits[stream_port] =\
                        get_stream_port_weighted_exits(stream_port, stream,
                        cons_rel_stats, descriptors,
                        cons_bw_weights, cons_bwweightscale)
                
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
                        descriptors, hibernating_status,\
                        stream_port_weighted_exits[stream_port],\
                        weighted_middles, weighted_guards,\
                        congmodel, pdelmodel)
                    if (not _testing):
                        print_mapped_stream(client_state['id'],\
                            stream_assigned, stream, descriptors, format)
            
            cur_time += time_step


def add_adv_guards(num_adv_guards, adv_relays, adv_descriptors, bandwidth):
    """"Adds adversarial guards into add_relays and add_descriptors."""
    for i in xrange(num_adv_guards):
        # create consensus
        num_str = str(i+1)
        fingerprint = '0' * (40-len(num_str)) + num_str
        nickname = 'BadGuyGuard' + num_str
        flags = [Flag.FAST, Flag.GUARD, Flag.RUNNING, \
            Flag.STABLE, Flag.VALID]
        adv_relays[fingerprint] = RouterStatusEntry(fingerprint, nickname,\
            flags, bandwidth)
            
        # create descriptor
        hibernating = False
        family = {}
        address = '10.'+num_str+'.0.0' # avoid /16 conflicts
        exit_policy = ExitPolicy('reject *:*')
        ntor_onion_key = num_str # anything but None to indicate ntor support
        adv_descriptors[fingerprint] = ServerDescriptor(fingerprint,\
            hibernating, nickname, family, address, exit_policy, ntor_onion_key)

def add_adv_exits(num_adv_guards, num_adv_exits, adv_relays, adv_descriptors,
    bandwidth):
    """"Adds adversarial exits into add_relays and add_descriptors."""
    for i in xrange(num_adv_exits):
        # create consensus
        num_str = str(i+1)
        fingerprint = 'F' * (40-len(num_str)) + num_str
        nickname = 'BadGuyExit' + num_str
        flags = [Flag.FAST, Flag.EXIT, Flag.RUNNING, \
            Flag.STABLE, Flag.VALID]
        adv_relays[fingerprint] = RouterStatusEntry(fingerprint, nickname,\
            flags, bandwidth)
            
        # create descriptor
        hibernating = False
        family = {}
        address = '10.'+str(num_adv_guards+i+1)+'.0.0' # avoid /16 conflicts
        exit_policy = ExitPolicy('accept *:*')
        ntor_onion_key = num_str # anything but None to indicate ntor support        
        adv_descriptors[fingerprint] = ServerDescriptor(fingerprint,
            hibernating, nickname, family, address, exit_policy, ntor_onion_key)
                        

def get_user_model(start_time, end_time, tracefilename=None, session='simple=6'):
    streams = []
    if (re.match('simple', session)):
        # simple user that makes a port 80 request /resolve every x / y seconds
        match = re.match('simple=([0-9]+)', session)
        if (match):
            num_requests = int(match.group(1))
        else:
            num_requests = 6
        http_request_wait = int(60 / num_requests) * 60
        str_ip = '74.125.131.105' # www.google.com
        for t in xrange(start_time, end_time, http_request_wait):
            streams.append({'time':t,'type':'connect','ip':str_ip,'port':80})
    else:
        ut = UserTraces.from_pickle(tracefilename)
        um = UserModel(ut, start_time, end_time)
        streams = um.get_streams(session)
    return streams


if __name__ == '__main__':
    command = None
    usage = 'Usage: pathsim.py [command]\nCommands:\n\
\tprocess \
[start_year] [start_month] [end_year] [end_month] [in_dir] [out_dir] [slim] [filtered]:\
 match relays in each consensus in in_dir/consensuses-[year]-[month] with \
descriptors in in_dir/server-descriptors-[year]-[month], where year and month \
range from start_year and start_month to end_year and end_month. Write the \
matched descriptors for each consensus to \
out_dir/network-state-[year]-[month]. Use slim classes if slim=1. Filter out relays without FAST and RUNNING flags if filtered=1.\n\
\tsimulate \
[nsf dir] [# samples] [tracefile] [user model] [output] [adv guard cons bw] [adv exit cons bw] [adv time] [num adv guards] [path selection alg] \
[num guards] [guard expiration]: \
Do simulated path selections, where\n\
\t\t nsf dir stores the network state files to use, \
default: out/network-state-files\n\
\t\t # samples is the number of simulations to execute, default: 1\n\
\t\t tracefile indicates the user trace, default: traces.pickle\n\
\t\t user model is one of "facebook", "gmailgchat", "gcalgdocs", "websearch", "irc", "bittorrent", "typical", "best", "worst", "simple=[reqs/hour]", default: "simple=6"\n\
\t\t output sets log level: 0 is normal, 1 is testing, 2 is for the relay adversary, 3 is for the network adversary, default: 0\n\
\t\t adv guard cons bw indicates the consensus bandwidth of the adversarial guard to add, \
default: 0\n\
\t\t adv exit cons bw indicates the consensus bandwidth of the adversarial exit to add, default: 0\n\
\t\t adv time indicates timestamp after which adv relays added to\
consensuses, default: 0\n\
\t\t num adv guards indicates the number of adversarial guards to add, default: 1\n\
\t\t path selection alg is one of\n\
\t\t\t tor: uses Tor path selection, is default\n\
\t\t\t cat [congfile]: uses congestion-aware tor with congfile is the congestion input file\n\
\t\t\t vcs [congfile] [pdelfile]: uses the virtual-coordinate system.\n\
\t\t num guards indicates size of client guard list, default: 3\n\
\t\t guard expiration indicates time in days until one-month period during \
which guard may expire, with 0 indicating no guard expiration, default: 30\n\
\tconcattraces \
outfilename.pickle facebook.log gmailgchat.log, gcalgdocs.log, websearch.log, irc.log, bittorrent.log: combine user session traces into a single object used by pathsim, and pickle it. The pickled object is input to the simulate command.'
    if (len(sys.argv) <= 1):
        print(usage)
        sys.exit(1)
        
    command = sys.argv[1]
    if (command != 'process') and (command != 'simulate') and (command != 'concattraces'):
        print(usage)
    elif (command == 'process'):
        if (len(sys.argv) < 10):
            print(usage)
            sys.exit(1)
        start_year = int(sys.argv[2])
        start_month = int(sys.argv[3])
        end_year = int(sys.argv[4])
        end_month = int(sys.argv[5])
        in_dir = sys.argv[6]
        out_dir = sys.argv[7]
        slim = (sys.argv[8] == '1')
        filtered = (sys.argv[9] == '1')

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
        process_consensuses.process_consensuses(in_dirs, slim, filtered)
    elif (command == 'simulate'):
        # get lists of consensuses and the related processed-descriptor files 
        network_state_files_dir = sys.argv[2] if len(sys.argv) >= 3 else 'out/network-state-files'
        num_samples = int(sys.argv[3]) if len(sys.argv) >= 4 else 1
        tracefilename = sys.argv[4] if len(sys.argv) >= 5 else "traces.pickle"
        usermodel = sys.argv[5] if len(sys.argv) >= 6 else 'simple=6'
        if (len(sys.argv) >= 7):
            level = int(sys.argv[6])
            if (level == 0):
                _testing = False
                format = 'normal'
            elif (level == 1):
                _testing = True
                format = 'testing'
            elif (level == 2):
                _testing = False
                format = 'relay-adv'
            elif (level == 3):
                _testing = False
                format = 'network-adv'
            else:
                _testing = False
                format = 'normal'
        else:
            format = 'normal'
            _testing = False
        adv_guard_cons_bw = float(sys.argv[7]) if len(sys.argv) >= 8 else 0
        adv_exit_cons_bw = float(sys.argv[8]) if len(sys.argv) >= 9 else 0
        adv_time = int(sys.argv[9]) if len(sys.argv) >= 10 else 0
        num_adv_guards = int(sys.argv[10]) if len(sys.argv) >= 11 else 1
        path_sel_alg = sys.argv[11] if len(sys.argv) >= 12 else 'tor'
        if (path_sel_alg == 'tor'):
            congfilename = None
            pdelfilename = None
            cur_arg = 13
        elif (path_sel_alg == 'cat'):
            congfilename = sys.argv[12] if len(sys.argv) >= 13 else None
            pdelfilename = None
            cur_arg = 14
        elif (path_sel_alg == 'vcs'):
            congfilename = sys.argv[12] if len(sys.argv) >= 13 else None
            pdelfilename = sys.argv[13] if len(sys.argv) >= 14 else None
            cur_arg = 15
        num_guards = int(sys.argv[cur_arg-1]) if (len(sys.argv) >= cur_arg)\
            else 3
        cur_arg += 1
        if (len(sys.argv) >= cur_arg):
            if (int(sys.argv[cur_arg-1]) > 0):
                guard_expiration_min = int(sys.argv[cur_arg-1])*24*3600
            else:
                # long enough that guard should never expire
                guard_expiration_min = int(100*365.25*24*3600)
        else:
            guard_expiration_min = 30*24*3600

        # use arguments to adjust some TorOption parameters
        TorOptions.num_guards = num_guards
        TorOptions.min_num_guards = max(num_guards-1, 1)
        TorOptions.guard_expiration_min = guard_expiration_min
        TorOptions.guard_expiration_max = guard_expiration_min + 30*24*3600
        
        network_state_files = []
        for dirpath, dirnames, filenames in os.walk(network_state_files_dir,\
            followlinks=True):
            for filename in filenames:
                if (filename[0] != '.'):
                    network_state_files.append(os.path.join(dirpath,filename))

        # insert gaps for missing time periods
        network_state_files.sort(key = lambda x: os.path.basename(x))
        network_state_files = pad_network_state_files(network_state_files)
        
        # determine start and end times
        start_time = None
        with open(network_state_files[0]) as nsf:
            consensus = pickle.load(nsf)
            start_time = timestamp(consensus.valid_after)
        end_time = None
        with open(network_state_files[-1]) as nsf:
            consensus = pickle.load(nsf)
            end_time = timestamp(consensus.fresh_until)

        # get our stream creation model from our user traces
        # available sessions:
        # "simple", "facebook", "gmailgchat", "gcalgdocs", "websearch", "irc", "bittorrent"
        streams = get_user_model(start_time, end_time, tracefilename,\
            session=usermodel)
        congmodel = CongestionModel(congfilename)
        pdelmodel = PropagationDelayModel(pdelfilename)
        
        num_adv_exits = 1
        adv_relays = {}
        adv_descriptors = {}
        # choose adversarial guards to add to network
        #bandwidth = 128000 # cons bw of top guard on 3/2/12
        add_adv_guards(num_adv_guards, adv_relays, adv_descriptors,
            adv_guard_cons_bw)

        # choose adversarial exits to add to network
        #bandwidth = 85000 # ~bw of top exit 3/2/12-4/30/12 (ZhangPoland1)
        add_adv_exits(num_adv_guards, num_adv_exits, adv_relays,
            adv_descriptors, adv_exit_cons_bw)
        
        
        if (path_sel_alg == 'cat'):
            create_circuit = congestion_aware_pathsim.create_circuit
            client_assign_stream = \
                congestion_aware_pathsim.client_assign_stream
        elif (path_sel_alg == 'vcs'):
            create_circuits = vcs_pathsim.create_circuits
            create_circuit = vcs_pathsim.create_circuit
            
        # simulate the circuits for these streams
        create_circuits(network_state_files, streams, num_samples,
            adv_relays, adv_descriptors, adv_time, congmodel, pdelmodel,
            format)              
    elif (command == 'concattraces'): 
        if len(sys.argv) != 9: print usage; sys.exit(1)           
        ut = UserTraces(sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8])
        ut.save_pickle(sys.argv[2])