import torps.ext.safest as safest
import itertools
import random
import logging
logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def main():

  relays = generate_random_relays(100)
  latency_map = generate_random_latency_map(relays)

  n_networks = 2

  client = safest.CoordinateEngineClient.Instance()
  client.set_logger(logger)
  client.connect("localhost",7000)

  """ 
  The setup call will block until it has initialized all of
  the networks by stepping them through the coordinate algorithm
  once
  """
  client.setup(n_networks,
              relays,
              latency_map,
              update_intvl = 3600,
              ping_intvl = 3)

  coords_n1 = client.get_next_coordinates(0)
  coord_1 = coords_n1[0]
  coords_n1 = client.get_next_coordinates(0)
  coord_2 = coords_n1[0]

  coord_change = coord_1.distance(coord_2)
  coords_n1 = client.get_next_coordinates(0)
  coord_1 = coords_n1[0]
  coords_n1 = client.get_next_coordinates(0)
  coord_2 = coords_n1[0]

  coord_change = coord_1.distance(coord_2)

  print("Coordinate for {0} changed {1} between iteration 1 and 2.\n"
        "Was previously {2}, now it is {3}"
        .format(
          coord_1.nodeid,
          coord_change,
          coord_1,
          coord_2))

  coords_n1 = client.get_next_coordinates(1)
  coord_1 = coords_n1[0]
  coords_n1 = client.get_next_coordinates(1)
  coord_2 = coords_n1[0]

  coord_change = coord_1.distance(coord_2)

  print("Coordinate for {0} changed {1} between iteration 1 and 2.\n"
        "Was previously {2}, now it is {3}"
        .format(
          coord_1.nodeid,
          coord_change,
          coord_1,
          coord_2))

class Relay():
  """A copy of the Relay class from readprofile.py """

  def __init__(self, name, isexit, isguard, weight):
    self.name = name
    self.isexit = isexit
    self.isguard = isguard
    self.weight = weight
    self.congestion = []

  def getrandom(self):
    return random.choice(self.congestion)


def generate_random_relays(num):
  """ Generates a random number of relay objects

  :num: The number of relays to generate
  :returns: a list of relays

  """
  generated = []

  class FakeCongestionProfile(object):
    name = None
    def __init__(self):
      pass

  profiles = []
  for i in xrange(50):
    r = FakeCongestionProfile()
    r.binsize = 10
    r.bins = [random.randint(0,10) for x in xrange(0,100)]
    profiles.append(r)

  for i in xrange(num):
    generated.append((str(i),random.choice(profiles)))

  return generated

def assign_congestion(relays, nvals):
  """ Assign congestion values to each relay in relays 

  :relays: A list of Relay objects
  :nvals: The number of congestion values to give each relay
  """
  for relay in relays:
    relay.congestion = [random.random()*10 for i in xrange(nvals)]

def generate_random_latency_map(relays, minval = 1, maxval = 20):
  """ Generate a random set of pairwise latencies for the
      relays

  :relays: the relays which should be included in the latency map
  :minval: the minimum latency
  :maxval: the maximum latency
  :returns: a dictionary which represents a latency map.

  """
  lmap = dict()
  for r1,r2 in itertools.combinations(map(lambda x: x[0],relays),2):
    try:
      lmap[r1][r2] = random.randint(minval,maxval)
    except KeyError:
      lmap[r1] = dict()
      lmap[r1][r2] = random.randint(minval,maxval)

  return lmap

if __name__ == '__main__':
  main()


