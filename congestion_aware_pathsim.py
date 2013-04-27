##### Versions of key Torps functions to implement congestion-aware Tor #####
# Re-implemented functions:
#   - create_circuit():
#     "Builds" k=3 circuits, measures congestion with m=5 circuit pings, and
#     chooses the best one. Also makes m additional pings and stores average.
#   - client_assign_stream():
#     If avg stored latency is > l=500ms, don't use. Ping after use and store.

import pathsim
from random import choice
import stem
import collections
from models import *

### Congestion-aware Tor parameters ###
client_ip = '74.125.131.105' # www.google.com
num_pings_create = 5 # number of measurements to choose built circuit to use
num_pings_use = 5 # number of measurements to record after use
min_ping = 500 # minimum ping to use circuit in milliseconds


def ping_circuit(client_ip, guard_node, middle_node, exit_node,\
    cons_rel_stats, descriptors, congmodel, pdelmodel):    
    ping_time = 0
    for node, coef in ((guard_node, 2), (middle_node, 2), (exit_node, 1)):
        rel_stat = cons_rel_stats[node]
        is_exit = (stem.Flag.EXIT in rel_stat.flags)
        is_guard = (stem.Flag.GUARD in rel_stat.flags)
        ping_time += coef*(congmodel.get_congestion(node,\
            rel_stat.bandwidth, is_exit, is_guard))

    # ca-tor subtracts minrtt from its pings to isolate congestion
    # so we dont actually want to include prop delay
    '''
    guard_ip = descriptors[guard_node]
    middle_ip = descriptors[middle_node]
    exit_ip = descriptors[exit_node]
    for ip, next_ip in ((client_ip, guard_ip), (guard_ip, middle_ip),\
        (middle_ip, exit_ip)):
        ping_time += pdelmodel.get_prop_delay(ip, next_ip)
        ping_time += pdelmodel.get_prop_delay(next_ip, ip)
    '''
    return ping_time


def create_circuit(cons_rel_stats, cons_valid_after, cons_fresh_until,\
    cons_bw_weights, cons_bwweightscale, descriptors, hibernating_status,\
    guards, circ_time, circ_fast, circ_stable, circ_internal, circ_ip,\
    circ_port,\
    congmodel, pdelmodel, weighted_exits=None,\
    exits_exact=False, weighted_middles=None, weighted_guards=None):
    """Creates path for requested circuit based on the input consensus
    statuses and descriptors. Uses congestion-aware path selection.
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
            'avg_ping': (float) average ping time during most-recent use
    """
#            'cons_rel_stats': (dict) relay stats for active consensus
    
    if (circ_time < cons_valid_after) or\
        (circ_time >= cons_fresh_until):
        raise ValueError('consensus not fresh for circ_time in create_circuit')
            
    # select exit node
    i = 1
    while (True):
        exit_node = pathsim.select_exit_node(cons_bw_weights,
            cons_bwweightscale, cons_rel_stats, descriptors, circ_fast,
            circ_stable, circ_internal, circ_ip, circ_port, weighted_exits,
            exits_exact)
#        exit_node = pathsim.select_weighted_node(weighted_exits)
        if (not hibernating_status[exit_node]):
            break
        if pathsim._testing:
            print('Exit selection #{0} is hibernating - retrying.'.\
                format(i))
        i += 1
    if pathsim._testing:    
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
        circ_guards = pathsim.get_guards_for_circ(cons_bw_weights,\
            cons_bwweightscale, cons_rel_stats, descriptors,\
            circ_fast, circ_stable, guards,\
            exit_node, circ_time, weighted_guards)   
        guard_node = choice(circ_guards)
        if (hibernating_status[guard_node]):
            if (not guards[guard_node]['made_contact']):
                if pathsim._testing:
                    print(\
                    '[Time {0}]: Removing new hibernating guard: {1}.'.\
                    format(circ_time, cons_rel_stats[guard_node].nickname))
                del guards[guard_node]
            elif (guards[guard_node]['unreachable_since'] != None):
                if pathsim._testing:
                    print(\
                    '[Time {0}]: Guard retried but hibernating: {1}'.\
                    format(circ_time, cons_rel_stats[guard_node].nickname))
                guards[guard_node]['last_attempted'] = circ_time
            else:
                if pathsim._testing:
                    print('[Time {0}]: Guard newly hibernating: {1}'.\
                    format(circ_time, \
                    cons_rel_stats[guard_node].nickname))
                guards[guard_node]['unreachable_since'] = circ_time
                guards[guard_node]['last_attempted'] = circ_time
        else:
            guards[guard_node]['unreachable_since'] = None
            guards[guard_node]['made_contact'] = True
            break
    if pathsim._testing:
        print('Guard node: {0} [{1}]'.format(
            cons_rel_stats[guard_node].nickname,
            cons_rel_stats[guard_node].fingerprint))
    
    # select middle node
    # As with exit selection, hibernating status checked here to mirror Tor
    # selecting middle, having the circuit fail, reselecting a path,
    # and attempting circuit creation again.    
    i = 1
    while (True):
        middle_node = pathsim.select_middle_node(cons_bw_weights,\
            cons_bwweightscale, cons_rel_stats, descriptors, circ_fast,\
            circ_stable, exit_node, guard_node, weighted_middles)
        if (not hibernating_status[middle_node]):
            break
        if pathsim._testing:
            print(\
            'Middle selection #{0} is hibernating - retrying.'.format(i))
        i += 1    
    if pathsim._testing:
        print('Middle node: {0} [{1}]'.format(
            cons_rel_stats[middle_node].nickname,
            cons_rel_stats[middle_node].fingerprint))

    cum_ping_time = 0
    if pathsim._testing: print 'Doing {0} circuit pings on creation... '.format(num_pings_create),
    for i in xrange(num_pings_create):
        cum_ping_time += ping_circuit(client_ip, guard_node, middle_node,\
            exit_node, cons_rel_stats, descriptors, congmodel, pdelmodel)
    avg_ping_time = float(cum_ping_time)/num_pings_create
    if pathsim._testing: print "ave congestion is {0}".format(avg_ping_time)
    
    return {'time':circ_time,\
            'fast':circ_fast,\
            'stable':circ_stable,\
            'internal':circ_internal,\
            'dirty_time':None,\
            'path':(guard_node, middle_node, exit_node),\
#            'cons_rel_stats':cons_rel_stats,\
            'covering':[],\
            'initial_avg_ping':avg_ping_time,
            'avg_ping':None}


def client_assign_stream(client_state, stream, cons_rel_stats,\
    cons_valid_after, cons_fresh_until, cons_bw_weights, cons_bwweightscale,\
    descriptors, hibernating_status, stream_weighted_exits,\
    weighted_middles, weighted_guards, congmodel, pdelmodel):
    """Assigns a stream to a circuit for a given client.
    Stores circuit measurements (pings) as would be measured during use."""
        
    guards = client_state['guards']
    stream_assigned = None

    # find dirty circuit with fastest initial_avg_ping
    for circuit in client_state['dirty_exit_circuits']:
        if ((circuit['avg_ping'] == None) or\
                (circuit['avg_ping'] <= min_ping)) and\
            pathsim.circuit_supports_stream(circuit, stream, descriptors) and\
            ((stream_assigned == None) or\
                (stream_assigned['initial_avg_ping'] > \
                    circuit['initial_avg_ping'])):
            stream_assigned = circuit
    # look for clean circuit with faster initial_avg_ping
    for circuit in client_state['clean_exit_circuits']:
        if ((circuit['avg_ping'] == None) or\
                (circuit['avg_ping'] <= min_ping)) and\
            pathsim.circuit_supports_stream(circuit, stream, descriptors) and\
            ((stream_assigned == None) or\
                (stream_assigned['initial_avg_ping'] > \
                    circuit['initial_avg_ping'])):
            stream_assigned = circuit
    # if circuit is clean, move to dirty list
    if (stream_assigned != None) and (stream_assigned['dirty_time'] == None):
        new_clean_exit_circuits = collections.deque()
        while (len(client_state['clean_exit_circuits']) > 0):
            circuit = client_state['clean_exit_circuits'].popleft()
            if (circuit == stream_assigned):
                circuit['dirty_time'] = stream['time']
                client_state['dirty_exit_circuits'].appendleft(circuit)
                new_clean_exit_circuits.extend(\
                    client_state['clean_exit_circuits'])
                client_state['clean_exit_circuits'].clear()
                if pathsim._testing:
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
                pathsim.uncover_circuit_ports(circuit,\
                    client_state['port_needs_covered'])
            else:
                new_clean_exit_circuits.append(circuit)
        client_state['clean_exit_circuits'] = new_clean_exit_circuits
    else:   
        if pathsim._testing:                                
            if (stream['type'] == 'connect'):
                print('Assigned CONNECT stream to port {0} to \
dirty circuit at {1}'.format(stream['port'], stream['time']))
            elif (stream['type'] == 'resolve'):
                print('Assigned RESOLVE stream to dirty circuit \
at {0}'.format(stream['time']))
            else:
                print('Assigned unrecognized stream to dirty circuit \
at {0}'.format(stream['time']))
            
    # if stream still unassigned we must make new circuit
    if (stream_assigned == None):
        new_circ = None
        if (stream['type'] == 'connect'):
            stable = (stream['port'] in pathsim.TorOptions.long_lived_ports)
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
        if pathsim._testing: 
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

    if pathsim._testing: print 'Doing {0} circuit pings on use... '.format(num_pings_use),
    cum_ping_time = 0
    guard_node = stream_assigned['path'][0]
    middle_node = stream_assigned['path'][1]
    exit_node = stream_assigned['path'][2]
    for i in xrange(num_pings_use):
        cum_ping_time += ping_circuit(client_ip, guard_node, middle_node,\
            exit_node, cons_rel_stats, descriptors, congmodel, pdelmodel)
    stream_assigned['avg_ping'] = float(cum_ping_time)/num_pings_use
    if pathsim._testing: print "ave congestion is {0}".format(stream_assigned['avg_ping'])
    
    return stream_assigned
