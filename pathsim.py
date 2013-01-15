import stem.descriptor.reader
import datetime

descriptor_dir = ["server-descriptors-2012-08"]
consensus_dir = "consensuses-2012-08"

if __name__ == "__main__":
    # read all descriptors into memory
    descriptors = {}
    num_descriptors = 0    
    num_relays = 0
    # read the same month of consensuses, skipping the first 18 hours (or, say, day) to
    # allow enough time for all relays in the consensus to have published a descriptor
    with stem.descriptor.reader.DescriptorReader(descriptor_dir) as reader:
        for desc in reader:
            num_descriptors += 1
            if ((num_descriptors-1) % 1000 == 0):
                print(num_descriptors)
            if (desc.fingerprint not in descriptors):
                descriptors[desc.fingerprint] = {}
                num_relays += 1
            td = desc.published - datetime.datetime(1970, 1, 1)
            ts = td.days*24*60*60 + td.seconds
            descriptors[desc.fingerprint][ts] = desc
    print("# descriptors: {0};  num_relays: {1}".format(num_descriptors,num_relays))            
    
    # read in consensuses
    # START
# create client
# every x minutes, choose another path according to current client state