import sys
import os
import pathsim

if __name__ == '__main__':
    usage = 'Usage: pathsim_analysis.py [command]\nCommands:\n\
\tnetwork [in_dir]:  Do some analysis on the network status files in in_dir.\n\
\tsimulation [in_dir]: Do some analysis on the simulation logs in in_dir.'
    if (len(sys.argv) <= 1):
        print(usage)
        sys.exit(1)
        
    command = sys.argv[1]
    if (command != 'network') and (command != 'simulation'):
        print(usage)
    elif (command == 'network'):
        if (len(sys.argv) < 3):
            print(usage)
            sys.exit(1)
        in_dir = sys.argv[2]
        print('in_dir: {0}'.format(in_dir))
        
        network_state_files = []
        for dirpath, dirnames, filenames in os.walk(in_dir, followlinks=True):
            for filename in filenames:
                if (filename[0] != '.'):
                    network_state_files.append(os.path.join(dirpath,filename))
        network_state_files.sort(key = lambda x: os.path.basename(x))
        for nsf in network_state_files:
            print(nsf)        
    elif (command == 'simulation'):
        if (len(sys.argv) < 3):
            print(usage)
            sys.exit(1)
        in_dir = sys.argv[2]