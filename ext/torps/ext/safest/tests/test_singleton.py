import sys
import os
sys.path = [os.path.abspath(os.path.dirname(__file__) + "/..")] + sys.path

import singleton
import unittest

@singleton.Singleton
class DummyClass(object):
  def __init__(self):
    self.blah = "blah"

class TestSingletons(unittest.TestCase):

  def test_singletons_cant_instantiate(self):
    self.assertRaises(TypeError, DummyClass)


  def test_is_singleton(self):

    t1 = DummyClass.Instance()
    t2 = DummyClass.Instance()

    assert t1 is t2

