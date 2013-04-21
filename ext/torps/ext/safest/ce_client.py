import protobuf as ext
import struct
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

class CommunicationError(Exception):
  pass

class ParseError(Exception):
  pass

@singleton.Singleton
class CoordinateEngineClient(object):

  def __init__(self):
    self.initialized = False
    self.socket= None
    self.log = logging.getLogger("CoordinateEngineClient")

  def connect(self,host,port):
    """
    Creates the CoordinateEngineClient, and establishes
    a TCP connection with the server. Note that setup()
    MUST still be called.
    """
    self.socket = socket.create_connection((host,port))

  def set_logger(self,logger):
    """
    Sets the log module to the passed argument. This allows
    you to hook this logging into more global logging streams.
    """
    self.log = logger

  def setup(self, num_networks, instances, latency_map, update_intvl = 3600, ping_intvl = 3 ):
    """
    Setup the CoordinateEngineClient with the specifics of
    the coordinate system that needs to be emulated. 'num_networks' copies of
    the coordinate system will be instantiated for separate samples.

    The most important argument is :instances:, which should a collection of tuples
    of the form (<nodeid>,<torps.CongestionProfile>).

    'latency_map' should be an adjacency list format designating the latency and
    links between pairs of nodes. For instances, {'n1': {'n2': 50 } } would
    designate a link between 'n1' and 'n2' with a cost of 50 milliseconds. The
    keys of the dictionary should be nodeids as provided in :instances:.

    There are two additional parameters, 'update_intvl' and 'ping_intvl',
    which specify, in seconds, the length of the coordinate system update
    and node ping intervals respectively.
    """
    if not isinstance(instances,(list,tuple)):
      raise TypeError("'instances' should be an iterable")

    msg = self.create_setup_message(num_networks,
                                    instances,
                                    latency_map,
                                    update_intvl,
                                    ping_intvl)

    self.send(msg.SerializeToString(),msg.ByteSize())

    self.initialized = True

  def send(self,buf,buflen,data_cb = None, **data_kwargs):
    tmpbuf = struct.pack("!I",buflen)
    tmpbuf += buf
    self.socket.sendall(tmpbuf)
    return self.wait_response(data_cb,**data_kwargs)

  def get_next_coordinates(self,network_id):
    """
    Requests and returns the next set of coordinates
    for all of the nodes in network 'network_id'.
    """
    req = ext.ControlMessage()
    req.type = ext.GET
    req.get_network_id = network_id

    coords = self.send(req.SerializeToString(),
                     req.ByteSize(),
                     self.translate_coordinate_response,
                     expected_network = network_id)

    return coords

  def read_msg_from_sock(self):
    resp = self.socket.recv(4)
    if resp <= 0:
      raise Exception("Lost connection to CoordinateEngine")
    msglen = struct.unpack("!I",resp)[0]
    self.log.debug("Read header indicating {0} byte message is next on the wire"
                    .format(msglen))

    resp = ""
    while len(resp) < msglen:
      resp += self.socket.recv(msglen - len(resp))
      self.log.debug("Waiting for {0} more bytes".format(msglen - len(resp)))

    return resp

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
    resp = self.read_msg_from_sock()

    msg = ext.StatusMessage()
    msg.ParseFromString(resp)
    if not msg.IsInitialized():
      raise CommunicationError("Received unparseable response from CoordinateEngine.")

    if msg.status == ext.StatusMessage.ERR:
      if msg.HasField("msg"):
        raise CommunicationError("CoordinateEngine returned error [{0}]".format(msg.msg))
      raise CommunicationError("CoordinateEngine returned generic error.")

    elif msg.status == ext.StatusMessage.OK:
      if msg.HasField("msg"):
        self.log.info(msg.msg)
      return ext.StatusMessage.OK

    elif msg.status == ext.StatusMessage.DATA_NEXT:
      self.log.debug("Server sent DATA_NEXT response. Listening")
      resp = self.read_msg_from_sock()
      results = data_cb(resp,**cb_args)
      return results

  @staticmethod
  def translate_coordinate_response(data,**kwargs):

    msg = ext.ControlMessage()
    msg.ParseFromString(data)
    if not msg.IsInitialized():
      raise ParseError("Unable to parse coordinate response")

    if msg.type != ext.COORDS or not msg.HasField("update_data"):
      raise ParseError("Expected coordinate response but didn't receive one.")

    coord_msg = msg.update_data
    if coord_msg.network_id != kwargs['expected_network']:
      raise ParseError("Coordinate response was for network {0}. Expected {1}."
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
    c_profiles = dict()

    init_msg = ext.ControlMessage()
    init_msg.type = ext.INIT
    init_msg.init_data.num_networks = num_networks
    init_msg.init_data.update_interval_seconds = update_intvl
    init_msg.init_data.ping_interval_seconds = ping_intvl

    for i,instance in enumerate(instances):
      if not isinstance(instance,(tuple,list)):
        raise TypeError("Expected instances to be tuples of the form (nodeid,congestion_profile)")
      
      nodeid = instance[0]
      profile = instance[1]
      if profile.name not in c_profiles:
        c_profiles[profile.name] = len(c_profiles)
        profile_buf = init_msg.init_data.congestion_profiles.add()
        profile_buf.identifier = c_profiles[profile.name]
        profile_buf.binsize = profile.binsize
        total_count = sum(profile.bins)
        for count in profile.bins:
          profile_buf.binprobs.append(float(count)/float(total_count))

      nodespec = init_msg.init_data.node_data.add()
      nodespec.id = nodeid
      nodespec.congestion_profile = c_profiles[profile.name]
      instance_idx_map[nodespec.id] = i

    if not isinstance(latency_map,(dict)):
      raise TypeError("'instances' should be a dictionary.")

    required_latencies = set(itertools.combinations(map(lambda x: x[0], instances),2))
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


