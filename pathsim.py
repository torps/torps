import stem.descriptor.reader as sdr
import datetime
import os.path
import stem.descriptor as sd
import stem.descriptor.networkstatus as sdn

# returns UNIX timestamp
def timestamp(t):
    td = t - datetime.datetime(1970, 1, 1)
    ts = td.days*24*60*60 + td.seconds
    return ts

descriptor_dir = ['server-descriptors-2012-08']
consensus_dir = 'consensuses-2012-08'
out_dir = 'out'
if __name__ == '__main__':
    # read all descriptors into memory
    descriptors = {}
    num_descriptors = 0    
    num_relays = 0
    with sdr.DescriptorReader(descriptor_dir) as reader:
        for desc in reader:
            num_descriptors += 1
            if ((num_descriptors-1) % 1000 == 0):
                print(num_descriptors)
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
            with open(os.path.join(dirpath,filename), 'r') as cf:
                relays = []
                cons_t = None
                for r_stat in sd.parse_file(os.path.abspath(filename), cf):
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
                        print('Descriptor not found for {0} : {1}:{2}'.format(r_stat.nickname,r_stat.fingerprint,pub_t))
                    else:
                        relays.append(descriptors[r_stat.fingerprint][desc_t])
                # output all discovered descriptors
                if cons_t:
                    outpath = os.path.join(out_dir,\
                        cons_t.strftime('%Y-%m-%d-%H-%M-%S-descriptor'))
                    f = open(outpath,'w')
                    for relay in relays:
                        # annotation needed for stem parser to work correctly
                        f.write('@type server-descriptor 1.0\n')
                        f.write(str(relay))
                        f.write('\n')
                    f.close()                
                num_consensuses += 1
    print('# consensuses: {0}'.format(num_consensuses))