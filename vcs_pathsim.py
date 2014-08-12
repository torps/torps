##### Versions of key Torps functions to implement virtual-coordinate Tor #####
# Re-implemented functions:
#   - create_circuits():
#     Initializes and updates network coordinates every consensus period.
#   - create_circuit():
#     "Builds" k=3 circuits, measures congestion with m=5 circuit pings, and
#     chooses the best one. Also makes m additional pings and stores average.

import os
from random import choice
import collections
from models import *

import pathsim

import torps.ext.safest as safest
import logging
logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


### VCS Tor parameters ###
num_paths_choose = 3 # number of paths to choose and predict latency for
######

def create_circuits(network_states, streams, num_samples, congmodel, pdelmodel, callbacks=None):
    """Takes streams over time and creates circuits by interaction
    with create_circuit().
      Input:
        network_states: iterator yielding NetworkState objects containing
            the sequence of simulation network states, with a None value
            indicating most recent status should be repeated with consensus
            valid/fresh times advanced 60 minutes
        streams: *ordered* list of streams, where a stream is a dict with keys
            'time': timestamp of when stream request occurs 
            'type': 'connect' for SOCKS CONNECT, 'resolve' for SOCKS RESOLVE
            'ip': IP address of destination
            'port': desired TCP port
        num_samples: (int) # circuit-creation samples to take for given streams
        congmodel: (CongestionModel) outputs congestion used by some path algs
        pdelmodel: (PropagationDelayModel) outputs prop delay
        callbacks: obj providing callback interface, cf. event_callbacks module
    Output:
        Uses callbacks to produce any desired output.
    """
    
    ### Simulation variables ###
    cur_period_start = None
    cur_period_end = None
    stream_start = 0
    stream_end = 0
    init = True

    # store old descriptors (for entry guards that leave consensus)
    descriptors = {}
    
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


    # SAFEST initialization    
    # SAFEST TODO: figure out how to do this
    # from ext/example.py:
    #   client = safest.CoordinateEngineClient.Instance()
    #   client.set_logger(logger)
    #   client.connect("localhost",7000)
    ### End simulation variables ###
    
    # run simulation period one network state at a time
    for network_state in network_states:
        if (network_state != None):
            cons_valid_after = network_state.cons_valid_after
            cons_fresh_until = network_state.cons_fresh_until
            cons_bw_weights = network_state.cons_bw_weights
            cons_bwweightscale = network_state.cons_bwweightscale
            cons_rel_stats = network_state.cons_rel_stats
            hibernating_statuses = network_state.hibernating_statuses
            new_descriptors = network_state.descriptors

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

        # update network state of callbacks object
        if (callbacks is not None):
            callbacks.set_network_state(cons_valid_after, cons_fresh_until,
                cons_bw_weights, cons_bwweightscale, cons_rel_stats,
                descriptors)        

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
        pathsim.set_initial_hibernating_status(hibernating_status,
            hibernating_statuses, cur_period_start)
        
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
            pathsim.period_client_update(client_state, cons_rel_stats,\
                cons_fresh_until, cons_valid_after)
                
        # update SAFEST network
        ### SAFEST TODO: figure out what to put here
        #n_networks = len(client_states)
        #relays = ### FILL IN ###
        #latency_map = ### FILL IN ###
        #client = safest.CoordinateEngineClient.Instance()
        #client.setup(n_networks,
        #    relays,
        #    latency_map,
        #    update_intvl = 3600,
        #    ping_intvl = 3)                

        # filter exits for port needs and compute their weights
        # do this here to avoid repeating per client
        port_need_weighted_exits = {}
        for port, need in port_needs_global.items():
            port_need_exits = pathsim.filter_exits(cons_rel_stats,
                descriptors, need['fast'], need['stable'], False, None, port)
            if _testing:
                print('# exits for port {0}: {1}'.\
                    format(port, len(port_need_exits)))
            port_need_exit_weights = pathsim.get_position_weights(\
                port_need_exits, cons_rel_stats, 'e', cons_bw_weights,\
                cons_bwweightscale)
            port_need_weighted_exits[port] =\
                pathsim.get_weighted_nodes(port_need_exits,
                    port_need_exit_weights)
                
        # Store filtered exits for streams based only on port.
        # Conservative - never excludes a relay that exits to port for some ip.
        # Use port of None to store exits for resolve circuits.
        stream_port_weighted_exits = {}

        # filter middles and precompute cumulative weights
        potential_middles = filter(lambda x: pathsim.middle_filter(x,
            cons_rel_stats, descriptors, None, None, None, None),
            cons_rel_stats.keys())
        if _testing:
            print('# potential middles: {0}'.format(len(potential_middles)))                
        potential_middle_weights = pathsim.get_position_weights(\
            potential_middles, cons_rel_stats, 'm', cons_bw_weights,
            cons_bwweightscale)
        weighted_middles = pathsim.get_weighted_nodes(potential_middles,\
            potential_middle_weights)
            
        # filter guards and precompute cumulative weights
        # New guards are selected infrequently after the experiment start
        # so doing this here instead of on-demand per client may actually
        # slow things down. We do it to improve scalability with sample number.
        potential_guards = pathsim.filter_guards(cons_rel_stats, descriptors)
        if _testing:
            print('# potential guards: {0}'.format(len(potential_guards)))        
        potential_guard_weights = pathsim.get_position_weights(\
            potential_guards, cons_rel_stats, 'g', cons_bw_weights,
            cons_bwweightscale)
        weighted_guards = pathsim.get_weighted_nodes(potential_guards,\
            potential_guard_weights)    
       
        # for simplicity, step through time one minute at a time
        time_step = 60
        cur_time = cur_period_start
        while (cur_time < cur_period_end):
            # do updates that apply to all clients    
            pathsim.timed_updates(cur_time, port_needs_global, client_states,
                hibernating_statuses, hibernating_status, cons_rel_stats)

            # do timed individual client updates
            for client_state in client_states:
                if (callbacks is not None):
                    callbacks.set_sample_id(client_state['id'])
                pathsim.timed_client_updates(cur_time, client_state,
                    port_needs_global, cons_rel_stats,
                    cons_valid_after, cons_fresh_until, cons_bw_weights,
                    cons_bwweightscale, descriptors, hibernating_status,
                    port_need_weighted_exits, weighted_middles,
                    weighted_guards, congmodel, pdelmodel, callbacks)
                    
            if _testing:
                for client_state in client_states:
                    print('Client {0}'.format(client_state['id']))
                    print('len(client_state[\'dirty_exit_circuits\']): {0}'.\
                        format(len(client_state['dirty_exit_circuits'])))
                    print('len(client_state[\'clean_exit_circuits\']): {0}'.\
                        format(len(client_state['clean_exit_circuits'])))
                    for pt, ct in client_state['port_needs_covered'].items():
                        print('port_needs_covered[{0}]: {1}'.format(pt,ct))

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
                pn_weighted_exits = pathsim.stream_update_port_needs(stream,
                    port_needs_global, client_states, descriptors,
                    cons_rel_stats, cons_bw_weights, cons_bwweightscale)
                if (pn_weighted_exits != None):
                    port_need_weighted_exits[port] = pn_weighted_exits
                            
                # stream port for purposes of using precomputed exit lists
                if (stream['type'] == 'resolve'):
                    stream_port = None
                else:
                    stream_port = stream['port']
                # create weighted exits for this stream's port
                if (stream_port not in stream_port_weighted_exits):
                    stream_port_weighted_exits[stream_port] =\
                        pathsim.get_stream_port_weighted_exits(stream_port,
                        stream, cons_rel_stats, descriptors,
                        cons_bw_weights, cons_bwweightscale)
                
                # do client stream assignment
                for client_state in client_states:
                    if (callbacks is not None):
                        callbacks.set_sample_id(client_state['id'])                
                    if _testing:                
                        print('Client {0} stream assignment.'.\
                            format(client_state['id']))
                    guards = client_state['guards']
                 
                    stream_assigned = pathsim.client_assign_stream(\
                        client_state, stream, cons_rel_stats,
                        cons_valid_after, cons_fresh_until,
                        cons_bw_weights, cons_bwweightscale,
                        descriptors, hibernating_status,
                        stream_port_weighted_exits[stream_port],
                        weighted_middles, weighted_guards,
                        congmodel, pdelmodel, callbacks)
            
            cur_time += time_step
            

def create_circuit(cons_rel_stats, cons_valid_after, cons_fresh_until,
    cons_bw_weights, cons_bwweightscale, descriptors, hibernating_status,
    guards, circ_time, circ_fast, circ_stable, circ_internal, circ_ip,
    circ_port, congmodel, pdelmodel, weighted_exits=None,
    exits_exact=False, weighted_middles=None, weighted_guards=None, callbacks=None):
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
        callbacks: object w/ method circuit_creation(circuit)        
    Output:
        circuit: (dict) a newly created circuit with keys
            'time': (int) seconds from time zero
            'fast': (bool) relays must have Fast flag
            'stable': (bool) relays must have Stable flag
            'internal': (bool) is internal (e.g. for hidden service)
            'dirty_time': (int) timestamp of time dirtied, None if clean
            'path': (tuple) list in-order fingerprints for path's nodes
            'covering': (set) ports with needs covered by circuit
    """
#            'cons_rel_stats': (dict) relay stats for active consensus
    
    if (circ_time < cons_valid_after) or\
        (circ_time >= cons_fresh_until):
        raise ValueError('consensus not fresh for circ_time in create_circuit')
    
    # choose num_paths_choose paths, and choose one with best predicted latency
    best_latency = None
    best_path = None
    for k in xrange(num_paths_choose):
        print('Choosing path #{0} to predict latency'.format(k))
        num_attempts = 0
        ntor_supported = False
        while (num_attempts < pathsim.TorOptions.max_populate_attempts) and\
            (not ntor_supported):        
            # select exit node
            i = 1
            while (True):
                exit_node = pathsim.select_exit_node(cons_bw_weights,
                    cons_bwweightscale,
                    cons_rel_stats, descriptors, circ_fast, circ_stable,
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
                circ_guards = pathsim.get_guards_for_circ(cons_bw_weights,\
                    cons_bwweightscale, cons_rel_stats, descriptors,\
                    circ_fast, circ_stable, guards,\
                    exit_node, circ_time, weighted_guards)   
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
                middle_node = pathsim.select_middle_node(cons_bw_weights,\
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
                    
            # ensure one member of the circuit supports the ntor handshake
            ntor_supported = pathsim.circuit_supports_ntor(guard_node, middle_node,
                exit_node, descriptors)
            num_attempts += 1
        if pathsim._testing:
            if ntor_supported:
                print('Chose ntor-compatible circuit in {} tries'.\
                    format(num_attempts))
        if (not ntor_supported):
            raise ValueError('ntor-compatible circuit not found in {} tries'.\
                format(num_attempts))
         
        latency = #SAFEST TODO: get latency for circuit from SAFEST VCS service
            
        if (best_latency == None) or (latency < best_latency):
            best_latency = latency
            best_circ = (guard_node, middle_node, exit_node)

    circuit = {'time':circ_time,
            'fast':circ_fast,
            'stable':circ_stable,
            'internal':circ_internal,
            'dirty_time':None,
            'path':best_circ,
            'covering':set(),
            'avg_ping':None}

    # execute callback to allow logging on circuit creation
    if (callbacks is not None):
        callbacks.circuit_creation(circuit)

    return circuit

    
