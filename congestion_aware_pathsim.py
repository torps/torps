##### Versions of key Torps functions to implement congestion-aware Tor #####
# Re-implemented functions:
#   - create_circuit():
#     "Builds" k=3 circuits, measures congestion with m=5 circuit pings, and
#     chooses the best one. Also makes m additional pings and stores average.
#   - circuit_supports_stream():
#     If average stored latency is > l=500ms, don't use.
#   - client_timed_update():
#     If average stored latency is > l=500ms, kill.


def ping_circuit(client_ip, guard_node, middle_node, exit_node,\
    cons_rel_stats, descriptors, congmodel, pdelmodel):    
    ping_time = 0
    for node, coef in ((guard_node, 1), (middle_node, 1), (exit_node, 2)):
        rel_stat = cons_rel_stats[node]
        is_exit = (stem.Flag.EXIT in rel_stat.flags)
        is_guard = (stem.Flag.GUARD in rel_stat.flags)
        ping_time += coef*(congmodel.get_congestion(node,\
            rel_stat.bandwidth, is_exit, is_guard))
    guard_ip = descriptors[guard_node]
    middle_ip = descriptors[middle_node]
    exit_ip = descriptors[exit_node]
    for ip, next_ip in ((client_ip, guard_ip), (guard_ip, middle_ip),\
        (middle_ip, exit_ip)):
        ping_time += pdelmodel.get_prop_delay(ip, next_ip)
        ping_time += pdelmodel.get_prop_delay(next_ip, ip)
    return ping_time


def create_circuit(cons_rel_stats, cons_valid_after, cons_fresh_until,\
    cons_bw_weights, cons_bwweightscale, descriptors, hibernating_status,\
    guards, circ_time, circ_fast, circ_stable, circ_internal, circ_ip,\
    circ_port, num_guards, min_num_guards, guard_expiration_min,\
    guard_expiration_max, congmodel, pdelmodel, weighted_exits=None,\
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
        num_guards - guard_expiration_max: various Tor parameters
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
        
    num_circuits = 3
    
    # for num_circuits successfully-created circuits, measure them
    # and choose the best one
    best_ping_time = None
    best_circ = None
    for k in xrange(num_test_circuits):
        print('Creating circuit to measure #{0}'.format(k))
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
            # get first <= num_guards guards suitable for circuit
            circ_guards = get_guards_for_circ(cons_bw_weights,\
                cons_bwweightscale, cons_rel_stats, descriptors,\
                circ_fast, circ_stable, guards, num_guards,\
                min_num_guards, exit_node, guard_expiration_min,\
                guard_expiration_max, circ_time, weighted_guards)   
            guard_node = choice(circ_guards)
            if (hibernating_status[guard_node]):
                if (not guards[guard_node]['made_contact']):
                    if _testing:
                        print(\
                        '[Time {0}]: Removing new hibernating guard: {1}.'.\
                        format(circ_time, cons_rel_stats[guard_node].nickname))
                    del guards[guard_node]
                elif (guards[guard_node]['unreachable_since'] != None):
                    if _testing:
                        print(\
                        '[Time {0}]: Guard retried but hibernating: {1}'.\
                        format(circ_time, cons_rel_stats[guard_node].nickname))
                    guards[guard_node]['last_attempted'] = circ_time
                else:
                    if _testing:
                        print('[Time {0}]: Guard newly hibernating: {1}'.\
                        format(circ_time, \
                        cons_rel_stats[guard_node].nickname))
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
            middle_node = select_middle_node(cons_bw_weights,\
                cons_bwweightscale, cons_rel_stats, descriptors, circ_fast,\
                circ_stable, exit_node, guard_node, weighted_middles)
            if (not hibernating_status[middle_node]):
                break
            if _testing:
                print(\
                'Middle selection #{0} is hibernating - retrying.'.format(i))
            i += 1    
        if _testing:
            print('Middle node: {0} [{1}]'.format(
                cons_rel_stats[middle_node].nickname,
                cons_rel_stats[middle_node].fingerprint))
         
        client_ip = '74.125.131.105' # www.google.com
        num_pings = 5
        cum_ping_time = 0
        print('Doing circuit pings')
        for i in xrange(num_pings):
            cum_ping_time += ping_circuit(client_ip, guard_node, middle_node,\
                exit_node, cons_rel_stats, descriptors, congmodel, pdelmodel)
            
        if (best_ping_time == None) or (cum_ping_time < best_ping_time):
            best_ping_time = cum_ping_time
            best_circ = (guard_node, middle_node, exit_node)
    
    return {'time':circ_time,\
            'fast':circ_fast,\
            'stable':circ_stable,\
            'internal':circ_internal,\
            'dirty_time':None,\
            'path':(best_circ),\
#            'cons_rel_stats':cons_rel_stats,\
            'covering':[]}