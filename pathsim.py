import stem.descriptor.reader as sdr
import datetime
import os
import os.path
import stem.descriptor as sd
import stem.descriptor.networkstatus as sdn

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
    
    with sdr.DescriptorReader(descriptor_dir) as reader:
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
            print(filename)
            with open(os.path.join(dirpath,filename), 'r') as cons_f:
                relays = []
                cons_t = None
                for r_stat in sd.parse_file(cons_f):
                    cons_t = r_stat.document.valid_after
                    # find descriptor published just before time in consensus
                    pub_t = timestamp(r_stat.published)
                    desc_t = 0
                    # get all descriptors with this fingerprint
                    if (r_stat.fingerprint in descriptors):
                        for t in descriptors[r_stat.fingerprint].keys():
                            if (t <= pub_t) and (t >= desc_t):
                                desc_t = t
                    if (desc_t == 0):
                        print('Descriptor not found for {0} : {1}:{2}'.format(\
                            r_stat.nickname,r_stat.fingerprint,pub_t))
                    else:
                        relays.append(descriptors[r_stat.fingerprint][desc_t])
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

def choose_paths(consensus_files, processed_descriptor_files, circuits):
    """Creates paths for requested circuits based on the inputs consensus
    and descriptor files.
    Inputs:
        consensus_files: list of consensus filenames *in correct order*
        processed_descriptor_files: descriptors corresponding to relays in
            consensus_files as produced by process_consensuses
        circuits: list of circuits to create, where a circuit is a tuple
            (time,fast,stable,internal,ip,port), where
                time(int): seconds from time zero
                fast(bool): indicates all relay must have Fast flag
                stable(bool): indicates all relay must have Stable flag
                internal(bool): indicates is for DNS or hidden service
                ip(str): ip address of destination
                port(int): port to connect to
    """
    i = 0
    for c_file, d_file in zip(consensus_files, processed_descriptor_files):
    # build a client with empty initial state  
    # go through consensuses, finding the processed descriptors for each
    # choose guards and do other pre-circuit setup
    # take in circuits to create:
    #   - dst ip
    #   - dst port
    #   - properties: fast, stable, exit/internal...

        with open(c_file) as cf, open(d_file) as df:
            # go through descriptors manually, adding them to dict 'desc'
            # go through consensus, adding more info to desc (e.g. flags)
            print(i)
        i += 1

    
if __name__ == '__main__':
#    descriptor_dir = ['in/server-descriptors-2012-08']
#    consensus_dir = 'in/consensuses-2012-08'
#    out_dir = 'out/processed-descriptors-2012-08'
#    process_consensuses(descriptor_dir, consensus_dir, out_dir)    

    consensus_dir = 'in/consensuses'
    descriptor_dir = 'out/descriptors'
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
    choose_paths(consensus_files, descriptor_files, circuits)