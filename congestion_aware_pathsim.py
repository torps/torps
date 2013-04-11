def client_assign_stream(client_state, stream, cons_rel_stats,\
    cons_valid_after, cons_fresh_until, cons_bw_weights, cons_bwweightscale,\
    descriptors, hibernating_status, num_guards, min_num_guards,\
    guard_expiration_min, guard_expiration_max, stream_weighted_exits,\
    weighted_middles, weighted_guards, long_lived_ports):
    """Uses congestion measurements to assign a stream to a circuit for a given
    client."""
        
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
                if (stream_assigned == None):
                    stream_assigned = circuit
                elif (circuit['congestion_time'] <\
                    stream_assigned['congestion_time']):
                    new_clean_exit_circuits.append(stream_assigned)
                    stream_assigned = circuit
                else:
                    new_clean_exit_circuits.append(circuit)
                  
        stream_assigned['dirty_time'] = stream['time']
        client_state['dirty_exit_circuits'].appendleft(stream_assigned)
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
        uncover_circuit_ports(stream_assigned,\
            client_state['port_needs_covered'])

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