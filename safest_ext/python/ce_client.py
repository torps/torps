import protobuf as ext
import itertools
import socket
import sys
import argparse
import logging
import singleton
logging.basicConfig()
logger = logging.getLogger("base")
logger.setLevel(logging.DEBUG)

class NodeInfo(object):

  def __init__(self,nodeid):
    self._nodeid = nodeid

  @property
  def nodeid(self):
    return self._nodeid

  @property
  def congestion_distribution(self):
    return self.congest

  @congestion_distribution.setter
  def congestion_distribution(self,dist):
    if not isinstance(dist, (list,tuple)):
      raise TypeError("Congestion distributions are expected "
                      "to be a list of numerical values.")

    if not all(map(lambda x: isinstance(x,(int,long,float)),dist )):
      raise TypeError("Not all passed values were numeric.")

    self.congest = dist[:]

@singleton.Singleton
class CoordinateEngineClient(object):

  """
  Creates the CoordinateEngineClient, and establishes
  a TCP connection with the server. Note that setup()
  MUST still be called.
  """
  def __init__(self):
    self.initialized = False
    self.socket= None

  def connect(self,host,port):
    self.socket = socket.create_connection((host,port))

  """
  Setup the CoordinateEngineClient with the specifics of 
  the coordinate system that needs to be emulated.

  The most important argument is 'instances', which should
  be a collection of NodeInfo objects, each of which contain
  the id, and congestion distribution for one of the nodes
  in the coordinate system.

  'latency_map' should be an adjacency list format designating the latency and
  links between pairs of nodes. For instances, {'n1': {'n2': 50 } } would
  designate a link between 'n1' and 'n2' with a cost of 50 milliseconds. The
  keys of the dictionary should be NodeInfo nodeids. 

  There are two additional parameters, 'update_intvl' and 'ping_intvl',
  which specify, in seconds, the length of the coordinate system update 
  and node ping intervals respectively.
  """
  def setup(self, instances, latency_map, update_intvl = 3600, ping_intvl = 3 ):

    if not isinstance(instances,(list,tuple)):
      raise TypeError("'instances' should be an iterable")

    msg = self.create_setup_message(instances,latency_map,update_intvl,ping_intvl)

    self.socket.sendall(msg.SerializeToString())

    self.initialized = True

  def create_setup_message(self,instances,latency_map, update_intvl, ping_intvl):
    """
    Do the actual work of creating the protocolbuffers message. 
    In a separate function so that we can test it properly.
    """
    instance_idx_map = dict()

    init_msg = ext.ControlMessage()
    init_msg.type = ext.INIT
    init_msg.init_data.update_interval_seconds = update_intvl
    init_msg.init_data.ping_interval_seconds = ping_intvl

    for i,instance in enumerate(instances):
      nodespec = init_msg.init_data.node_data.add()
      try:
        nodespec.id = instance.nodeid
        nodespec.congestion_dist.extend(instance.congestion_distribution)
      except AttributeError:
        raise TypeError("Expected 'instances' to be an iterable of NodeInfo objects")
      instance_idx_map[instance.nodeid] = i

    if not isinstance(latency_map,(dict)):
      raise TypeError("'instances' should be a dictionary.")

    required_latencies = set(itertools.combinations(map(lambda x: x.nodeid, instances),2))
    for n1,n2,lat in self.__yield_latency_info(latency_map):
      if len(set([(n1,n2),(n2,n1)]) & required_latencies) == 0:
        continue
      l_info = init_msg.init_data.latency_map.add()
      l_info.n1_idx = instance_idx_map[ n1 ]
      l_info.n2_idx = instance_idx_map[ n2 ]
      l_info.latency = lat
      required_latencies -= set([(n1,n2),(n2,n1)])

    if len(required_latencies) > 0:
      raise AttributeError("Latency map provides no value for '{0}'"
                            .format(required_latencies))

    return init_msg

  def __yield_latency_info(self,latency_map):
    for n1,links in latency_map.iteritems():
      for n2,lat in links.iteritems():
        try:
          flat = float(lat)
        except:
          raise TypeError("Latency value '{0}' couldn't be converted to float."
                          .format(lat))
        yield (n1,n2,flat)


