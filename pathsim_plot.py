# Isolate code that uses numpy and matplotlib here
# so pypy can be used with the rest.

import sys
import numpy
import matplotlib
matplotlib.use('PDF') # alerts matplotlib that display not required
import matplotlib.pyplot
#import matplotlib.mlab
import math