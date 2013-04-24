import pathsim
import stem.descriptor.reader as sdr

def process_consensuses(in_dirs, slim, filtered):
    """For every input consensus, finds the descriptors published most recently before the descriptor times listed for the relays in that consensus, records state changes indicated by descriptors published during the consensus fresh period, and writes out pickled consensus and descriptor objects with the relevant information.
        Inputs:
            in_dirs: list of (consensus in dir, descriptor in dir, \
                processed descriptor out dir) triples *in order*
            slim: Whether to use custom slim classes or Stem classes.
            filtered: Whether to exclude relays without Running & Fast flags
    """
    descriptors = {}
    def skip_listener(path, exception):
        print('ERROR [{0}]: {1}'.format(path.encode('ascii', 'ignore'), exception.__unicode__().encode('ascii','ignore')))
        
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
                descriptors[desc.fingerprint]\
                    [pathsim.timestamp(desc.published)] = desc
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
            descriptors_out = {}
            hibernating_statuses = [] # (time, fprint, hibernating)
            cons_valid_after = None
            cons_fresh_until = None
            if slim:
                cons_bw_weights = None
                cons_bwweightscale = None
                relays = {}
            else:
                consensus = None
            num_not_found = 0
            num_found = 0
            for r_stat in sd.parse_file(cons_f, validate=True):
                if (cons_valid_after == None):
                    cons_valid_after = r_stat.document.valid_after
                    # compute timestamp version once here
                    valid_after_ts = pathsim.timestamp(cons_valid_after)
                if (cons_fresh_until == None):
                    cons_fresh_until = r_stat.document.fresh_until
                    # compute timestamp version once here
                    fresh_until_ts = pathsim.timestamp(cons_fresh_until)
                if slim:
                    if (cons_bw_weights == None):
                        cons_bw_weights = r_stat.document.bandwidth_weights
                    if (cons_bwweightscale == None) and \
                        ('bwweightscale' in r_stat.document.params):
                        cons_bwweightscale = r_stat.document.params[\
                                'bwweightscale']
                if slim:
                    relays[r_stat.fingerprint] = RouterStatusEntry(\
                        r_stat.fingerprint, r_stat.nickname, \
                        r_stat.flags, r_stat.bandwidth)
                else:
                    if (consensus == None):
                        consensus = r_stat.document

                # find most recent unexpired descriptor published before
                # the publication time in the consensus
                # and status changes in fresh period (i.e. hibernation)
                pub_time = pathsim.timestamp(r_stat.published)
                desc_time = 0
                descs_while_fresh = []
                desc_time_fresh = None
                # get all descriptors with this fingerprint
                if (r_stat.fingerprint in descriptors):
                    for t,d in descriptors[r_stat.fingerprint].items():
                        # update most recent desc seen before cons pubtime
                        # allow pubtime after valid_after but not fresh_until
                        if (valid_after_ts-t <\
                            pathsim.TorOptions.router_max_age) and\
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
                    num_found += 1
                    # store discovered recent descriptor
                    desc = descriptors[r_stat.fingerprint][desc_time]
                    if slim:
                        descriptors_out[r_stat.fingerprint] = \
                            ServerDescriptor(desc.fingerprint, \
                                desc.hibernating, desc.nickname, \
                                desc.family, desc.address, \
                                desc.exit_policy)
                    else:
                        descriptors_out[r_stat.fingerprint] = desc
                     
                    # store hibernating statuses
                    if (desc_time_fresh == None):
                        raise ValueError('Descriptor error for {0}:{1}.\n Found  descriptor before published date {2}: {3}\nDid not find descriptor for initial hibernation status for fresh period starting {4}.'.format(r_stat.nickname, r_stat.fingerprint, pub_time, desc_time, valid_after_ts))
                    desc = descriptors[r_stat.fingerprint][desc_time_fresh]
                    cur_hibernating = desc.hibernating
                    # setting initial status
                    hibernating_statuses.append((0, desc.fingerprint,\
                        cur_hibernating))
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
                if slim:
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

                print('Wrote descriptors for {0} relays.'.\
                    format(num_found))
                print('Did not find descriptors for {0} relays\n'.\
                    format(num_not_found))
            else:
                print('Problem parsing {0}.'.format(filename))             
            num_consensuses += 1
            
            cons_f.close()
                
        print('# consensuses: {0}'.format(num_consensuses))
