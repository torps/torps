import sys
import os
import unittest

sys.path = [os.path.abspath(os.path.dirname(__file__) + "/..")] + sys.path
import protobuf as ext
import coordinate

class TestNodeInfo(unittest.TestCase):

  def setUp(self):
    self.c1 = ext.Coordinate()
    self.c1.node_id = "n1"
    self.c1.dim = 3
    self.c1.error = 0.25
    for x in (3.14,15.923, 323.11):
      self.c1.vectors.append(x)
    self.c2 = ext.Coordinate()
    self.c2.node_id = "n2"
    self.c2.dim = 3
    self.c2.error = 0.42
    for x in (3.21,21.0,1442.2):
      self.c2.vectors.append(x)

  def test_from_proto(self):
    coord = coordinate.Coordinate.from_protobuf(self.c1)
    assert isinstance(coord,coordinate.Coordinate)

  def test_distance(self):
    coord1 = coordinate.Coordinate.from_protobuf(self.c1)
    coord2 = coordinate.Coordinate.from_protobuf(self.c2)

    assert coord1.distance(coord2) - 1119.10151 < 0.001
