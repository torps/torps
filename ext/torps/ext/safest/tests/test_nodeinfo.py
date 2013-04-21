import sys
import os
import unittest
import mock

sys.path = [os.path.abspath(os.path.dirname(__file__) + "/..")] + sys.path
import ce_client
import protobuf as ext

def assign_clist(ni,val):
  ni.congestion_distribution = val

class TestNodeInfo(unittest.TestCase):

  def test_raises_if_clist_not_iterable(self):
    ni = ce_client.NodeInfo("james")

    self.assertRaises(TypeError,assign_clist,ni,"stringtest")

  def test_raises_if_nonnumeric(self):
    ni = ce_client.NodeInfo("james")

    self.assertRaises(TypeError,assign_clist,ni,[10,3,4,"ja"])

class TestCoordinateEngineClient(unittest.TestCase):

  def setUp(self):
    def fake_create_connection(addr):
      return True
    ce_client.socket.create_connection = fake_create_connection
    self.cli = ce_client.CoordinateEngineClient.Instance()

  def test_connect(self):
    assert self.cli.initialized is False
    assert self.cli.socket is None

    self.cli.connect("fakehost",1234)
    assert self.cli.socket is True

  def test_raises_on_noniterable_instances(self):
    self.assertRaises(TypeError,self.cli.setup,2,"false","false")

  def test_raises_on_non_NodeInfo_instances(self):
    self.assertRaises(TypeError,self.cli.setup,2,["randomstring"],"false")

  def test_checks_latency_map(self):

    n1 = ce_client.NodeInfo("james")
    n1.congestion_distribution = [1,2,3]
    n2 = ce_client.NodeInfo("bond")
    n2.congestion_distribution = [4,5,6]
    n3 = ce_client.NodeInfo("shaken")
    n3.congestion_distribution = [7,8,9]
    invalid_map = dict()
    invalid_map[n1.nodeid] = dict()
    invalid_map[n1.nodeid][n2.nodeid] = 50.0
    invalid_map[n1.nodeid][n3.nodeid] = 8

    self.assertRaises(TypeError,self.cli.setup,2,(n1,n2),(n1,n2))

    with self.assertRaises(AttributeError) as cm:
      self.cli.setup(2,(n1,n2,n3),invalid_map)

  def test_creates_valid_messages(self):
    n1 = ce_client.NodeInfo("james")
    n1.congestion_distribution = [1,2,3]
    n2 = ce_client.NodeInfo("bond")
    n2.congestion_distribution = [4,5,6]
    n3 = ce_client.NodeInfo("shaken")
    n3.congestion_distribution = [7,8,9]
    valid_map = dict()
    valid_map[n1.nodeid] = dict()
    valid_map[n1.nodeid][n2.nodeid] = 50.0
    valid_map[n1.nodeid][n3.nodeid] = 8

    init_msg = self.cli.create_setup_message(2,(n1,n2),valid_map,40,2)
    msg = init_msg.SerializeToString()

    parsed_msg = ext.ControlMessage()
    parsed_msg.ParseFromString(msg)

    assert parsed_msg.type == ext.INIT
    assert parsed_msg.HasField("init_data")
    assert parsed_msg.init_data.update_interval_seconds == 40
    assert parsed_msg.init_data.ping_interval_seconds == 2
    assert parsed_msg.init_data.num_networks == 2
    assert n1.nodeid in map(lambda x: x.id, parsed_msg.init_data.node_data)
    assert n2.nodeid in map(lambda x: x.id, parsed_msg.init_data.node_data)



