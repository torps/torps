import stem.descriptor.reader as sdr
import datetime
import os.path
import stem.descriptor.networkstatus as sdn

# returns UNIX timestamp
def timestamp(dt):
    td = dt - datetime.datetime(1970, 1, 1)
    ts = td.days*24*60*60 + td.seconds
    return ts

descriptor_dir = ['server-descriptors-2012-08']
consensus_dir = 'consensuses-2012-08-stripped'

if __name__ == '__main__':
    """
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
    print('#descriptors: {0}; #relays:{1}'.format(num_descriptors,num_relays))
    """    
    # read in all consensuses into memory
    consensuses = {}
    num_consensuses = 0
    for dirpath, dirnames, filenames in os.walk(consensus_dir):
        for filename in filenames:
            with open(os.path.join(dirpath,filename), 'r') as cf:
                consensus = sdn.NetworkStatusDocumentV3(cf.read())
                print(consensus.valid_after.strftime('%Y-%m-%d %H-%M-%S'))
                consensuses[timestamp(consensus.valid_after)] = consensus
                num_consensuses += 1
    print('# consensuses: {0}'.format(num_consensuses))
            
# create client
# every x minutes, choose another path according to current client state