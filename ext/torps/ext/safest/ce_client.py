import protobuf as ext
import itertools
import socket
import sys
import argparse
import logging
import coordinate
import singleton
logging.basicConfig()
logger = logging.getLogger("base")
logger.setLevel(logging.DEBUG)

class NodeInfo(object):

  def __init__(self,nodeid):
    self._nodeid = nodeid

  @classmethod
  def from_Relay(cls,relay):
    """
    Creates a NodeInfo object from a readprofile.Relay
    object. 
    """
    try:
      ni = NodeInfo(relay.name)
      ni.congestion_distribution = relay.congestion
    except AttributeError as e:
      raise TypeError("Expected an object of type 'readprofile.Relay', but "
                      "encountered an error while accessing it: {0}".format(e))

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

  class CommunicationError(Exception):
    pass

  class ParseError(Exception):
    pass

  def __init__(self):
    self.initialized = False
    self.socket= None
    self.log = logging.getLogger("CoordinateEngineClient")

  """
  Creates the CoordinateEngineClient, and establishes
  a TCP connection with the server. Note that setup()
  MUST still be called.
  """
  def connect(self,host,port):
    self.socket = socket.create_connection((host,port))

  def set_logger(self,logger):
    """
    Sets the log module to the passed argument. This allows
    you to hook this logging into more global logging streams.
    """
    self.log = logger

  """
  Setup the CoordinateEngineClient with the specifics of 
  the coordinate system that needs to be emulated. 'num_networks' copies of
  the coordinate system will be instantiated for separate samples.

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
  def setup(self, num_networks, instances, latency_map, update_intvl = 3600, ping_intvl = 3 ):

    if not isinstance(instances,(list,tuple)):
      raise TypeError("'instances' should be an iterable")

    msg = self.create_setup_message(num_networks,
                                    instances,
                                    latency_map,
                                    update_intvl,
                                    ping_intvl)

    self.send(msg.SerializeToString())

    self.initialized = True

  def send(self,buf,data_cb = None):
    self.socket.sendall(buf,data_cb)
    self.wait_response()

  def get_next_coordinates(self,network_id):
    """
    Requests and returns the next set of coordinates 
    for all of the nodes in network 'network_id'.
    """

    req = ext.ControlMessage()
    req.type = ext.GET
    req.get_network_id = network_id

    return self.send(req.SerializeToString(),
                     CoordinateEngineClient.translate_coordinate_response,
                     expected_network = network_id)

  def wait_response(self,data_cb = None, **cb_args):
    """
    Wait for a response from the coordinate engine 
    telling you whether or not the command was
    successful or not.

    If data was returned and 'data_cb' is provided,
    it will be called with the received data buffer as 
    the first argument, and the keyword arguments in 'cb_args'.

    This function will return ext.StatusMessage.OK or the
    return value of 'data_cb'.
    """
    resp = self.socket.recv(256,socket.MSG_WAITALL)

    msg = ext.StatusMessage.ParseFromString(resp)
    if not msg:
      raise self.CommunicationError("Received unparseable response from CoordinateEngine.")

    if msg.status == ext.StatusMessage.ERR:
      if msg.HasField("msg"):
        raise self.CommunicationError("CoordinateEngine returned error [{0}]".format(msg.msg))
      raise self.CommunicationError("CoordinateEngine returned generic error.")

    elif msg.status == ext.StatusMessage.OK:
      if msg.HasField("msg"):
        self.log.info(msg.msg)
      return ext.StatusMessage.OK

    elif msg.status == ext.StatusMessage.DATA_NEXT:
      self.log.debug("Server sent DATA_NEXT response. Listening")
      resp = self.socket.recv(8192,socket.MSG_WAITALL)
      return data_cb(resp,**cb_args)

  @staticmethod
  def translate_coordinate_response(data,**kwargs):

    msg = ext.ControlMessage.ParseFromString(data)
    if not msg:
      raise CoordinateEngineClient.ParseError("Unable to parse coordinate response")

    if msg.type != ext.COORDS or not msg.HasField("update_data"):
      raise CoordinateEngineClient.ParseError("Expected coordinate response but didn't receive one.")

    coord_msg = msg.update_data
    if coord_msg.network_id != kwargs['expected_network']:
      raise CoordinateEngineClient.ParseError("Coordinate response was for network {0}. Expected {1}."
                                              .format(coord_msg.network_id,kwargs['expected_network']))

    coords = list()
    for coord_data in coord_msg.coords:
      coords.append(coordinate.Coordinate.from_protobuf(coord_data))

    return coords

  def create_setup_message(self,num_networks, instances,latency_map, update_intvl, ping_intvl):
    """
    Do the actual work of creating the protocolbuffers message. 
    In a separate function so that we can test it properly.
    """
    instance_idx_map = dict()

    init_msg = ext.ControlMessage()
    init_msg.type = ext.INIT
    init_msg.init_data.num_networks = num_networks
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


