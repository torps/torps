#!/usr/bin/python

"""
run portscan.py in parallel using processes.
"""
import os, sys

if len(sys.argv) != 3: print "USAGE: {0} network_state_dir nthreads".format(sys.argv[0]);sys.exit()

def main():
    from threading import Thread
    from Queue import Queue
    from time import sleep

    nsfs = get_network_state_files(sys.argv[1])
    # create our job queue                                                                                                                   
    jobs = Queue()

    # spawn thread pool                                                                                                                      
    for id in range(int(sys.argv[2])):
        worker = Thread(target=launch, args=(id, jobs))
        worker.setDaemon(True)
        worker.start()

    # add work                                                                                                                            
    for nsf in nsfs:
        cmd = "/usr/bin/pypy util/portscan.py {0}".format(nsf)
        jobs.put(cmd)
#        sleep(1)

    # wait until worker threads are done with jobs to exit                                                                          
    jobs.join()

def launch(id, jobs):
    import subprocess

    while True:
        runcmd = jobs.get()
 
#        print "Thread %s: Running '%s'" % (str(id), runcmd)
        ret = subprocess.call(runcmd, shell=True, stderr=subprocess.STDOUT)
#        print "Thread %s: Command '%s' returned %s" % (str(id), runcmd, str(ret))

        jobs.task_done()

def get_network_state_files(network_state_dir):
    nsfs = []
    for dirpath, dirnames, filenames in os.walk(network_state_dir, followlinks=True):
        for filename in filenames:
            if (filename[0] != '.'):
                nsfs.append(os.path.join(dirpath,filename))
    nsfs.sort(key = lambda x: os.path.basename(x))
    return nsfs

if __name__ == '__main__':
    main()
