
class Coordinate(object):

  def __init__(self):
    self._built = False

  def distance(self,other):
    import math
    d_sum = reduce(lambda acc, x: acc + (x[0] - x[1])**2,zip(other.vectors, self.vectors), 0)
    return math.sqrt(d_sum)

  @classmethod
  def from_protobuf(cls,pbuf):
    coord = Coordinate()
    coord._nid = pbuf.node_id
    coord._err = pbuf.error
    coord._v = tuple([v for v in pbuf.vectors])
    coord._built = True
    return coord

  def __repr__(self):
    if not self._built:
      return "None"
    return "%s" % ({"nodeid": self.nodeid,
        "vectors": self.vectors[:],
        "error":self.error })

  @property
  def nodeid(self):
    if not self._built:
      raise Exception("Coordinate uninitialized.")
    return self._nid

  @property
  def dimensions(self):
    if not self._built:
      raise Exception("Coordinate uninitialized.")
    return len(self._v)

  @property
  def vectors(self):
    if not self._built:
      raise Exception("Coordinate uninitialized.")
    return self._v

  @property
  def error(self):
    if not self._built:
      raise Exception("Coordinate uninitialized.")
    return self._err
