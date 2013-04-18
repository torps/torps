from bisect import bisect_left
from random import random, randint
import cPickle as pickle
import datetime

class UserTraces(object):
    """
Format:
------
Each trace file contains a user session in the form:

TIME IP PORT

where each line represents a new stream, TIME is the stream creation timestamp in normalized seconds since the first stream in the session, IP is the destination target of the stream as reported by Tor, and PORT is the destination port of the stream as reported by Tor.

    """
    @staticmethod
    def from_pickle(filename):
        with open(filename, 'rb') as f: return pickle.load(f)

    def __init__(self, facebookf, gmailgchatf, gcalgdocsf, websearchf, ircf, bittorrentf):
        self.trace = {}
        for (key, filename) in [("facebook",facebookf) , ("gmailgchat",gmailgchatf), ("gcalgdocs",gcalgdocsf), ("websearch",websearchf), ("irc",ircf), ("bittorrent",bittorrentf)]:
            self.trace[key] = []
            with open(filename, 'rb') as f:
                for line in f:
                    parts = line.strip().split()
                    seconds, ip, port = float(parts[0]), parts[1], int(parts[2])
                    self.trace[key].append((seconds, ip, port))

    def save_pickle(self, filename):
        with open(filename, 'wb') as f: pickle.dump(self, f)


class UserModel(object):
    """
Sessions:
--------
We collected session traces of approximately 20 minutes for each usage class. We convert these into usage over time by repeating each trace as indicated by the following weekly usage schedule.

-facebook      }
-gmail/gchat   } 6:30-7am (1 session) M-F, 6-7pm (3 sessions) M-F
-gcal/gdocs    }
-web search    }
-irc             8am-5pm (27 sessions) M-F
-bittorrent      12pm-6am (18 sessions) Su-Sa
    """
    def __init__(self, usertraces, starttime, endtime):
        self.model = {}
        self.schedule = {}
        day = 86400

        # first set up the weekly schedule for each session type
        for key in ["facebook", "gmailgchat", "gcalgdocs", "websearch"]:
            self.schedule[key] = []
            trace = usertraces.trace[key]
            monmorn, monnight = 109800, 151200
            for (morning, night) in [(monmorn, monnight), (monmorn+day, monnight+day), (monmorn+day*2, monnight+day*2), (monmorn+day*3, monnight+day*3), (monmorn+day*4, monnight+day*4)]:
                sessionend = self.schedule_session(key, trace, morning) # 0630
                sessionend = self.schedule_session(key, trace, night) # 1800
                sessionend = self.schedule_session(key, trace, sessionend) # after above session
                sessionend = self.schedule_session(key, trace, sessionend) # after above session
        for key in ["irc"]:
            self.schedule[key] = []
            trace = usertraces.trace[key]
            monmorn = 115200
            for morning in [monmorn, monmorn+day, monmorn+day*2, monmorn+day*3, monmorn+day*4]:
                sessionend = self.schedule_session(key, trace, morning)
                for i in xrange(26):
                    sessionend = self.schedule_session(key, trace, sessionend)
        for key in ["bittorrent"]:
            self.schedule[key] = []
            trace = usertraces.trace[key]
            sunmorn = 0
            for morning in [sunmorn, sunmorn+day, sunmorn+day*2, sunmorn+day*3, sunmorn+day*4, sunmorn+day*5, sunmorn+day*6]:
                sessionend = self.schedule_session(key, trace, morning)
                for i in xrange(17):
                    sessionend = self.schedule_session(key, trace, sessionend)

        # then build the model during the requested interval
        startd = datetime.datetime.fromtimestamp(starttime)
        offset = startd.weekday()*3600*24 + startd.hour*3600 + startd.minute*60 + startd.second
        endd = datetime.datetime.fromtimestamp(endtime)
        for key in self.schedule:
            self.model[key] = []
            currenttime = 0
            week = 0
            while currenttime < endtime:
                for (seconds, ip, port) in self.schedule[key]:
                    seconds = seconds + week*604800
                    if currenttime < offset and seconds < offset: continue
                    currenttime = seconds-offset+starttime
                    if currenttime >= endtime: break
                    self.model[key].append({'time':currenttime,'type':'connect','ip':ip,'port':port})
                week += 1

    def schedule_session(self, key, trace, sessionstart):
        s = 0
        for (seconds, ip, port) in trace:
            s = sessionstart+seconds
            self.schedule[key].append((s, ip, port))
        if s < sessionstart+20*60: s = sessionstart+20*60 # assume session took at least 20 minutes
        return s

    def get_streams(self, session):
        return self.model[session]

class Relay():

    def __init__(self, name, isexit, isguard, weight):
        self.name = name
        self.isexit = isexit
        self.isguard = isguard
        self.weight = weight
        self.congestion = []

class CongestionProfile(object):
    """
    """
    def __init__(self, relay):

        self.name = relay.name
        self.isexit = relay.isexit
        self.isguard = relay.isguard
        self.weight = relay.weight

        self.lenc = len(relay.congestion)
        self.minc, self.maxc = 1000*min(relay.congestion), 1000*max(relay.congestion)
        self.binsize = int((self.maxc-self.minc)/100.0)
        self.breakpoints = range(self.minc, self.maxc, self.binsize)
        self.bins = [0 for i in self.breakpoints]

        for c in relay.congestion:
            i = bisect_left(self.breakpoints, c*1000.0)
            self.bins[i] += 1

    def get_congestion(self):
        # probabilistically choose a bin
        x = random() * self.lenc
        i = bisect_left(self.bins, x)
        # draw a uniform value from its range
        low = self.breakpoints[i]
        high = low + self.binsize
        return (randint(low, high) / 1000.0)

class CongestionModel(object):
    """
    """
    def __init__(self, tracefilename):

        self.assigned = {}
        self.profiles = {}

        relays = None
        with open(tracefilename, 'rb') as inf:
            relays = pickle.load(inf)
            for name in relays: self.profiles[name] = CongestionProfile(relays[name])

    '''
    Gets the relay profile with a consensus weight closest to the given
    weight, taking into consideration the exit and guard flags.
    Returns the match or None. (We currently have no guard-only profiles.)
    '''
    def find_match(self, weight, isexit=False, isguard=False):
        match, dist = None, None
        for name in self.profiles:
            r = self.profiles[name]
            if isexit != r.isexit or isguard != r.isguard: continue
            d = abs(weight-r.weight)
            if match is None or d < dist:
                match = r
                dist = d
        return match

    def get_congestion(self, name, weight, isexit=False, isguard=False):
        if name not in self.assigned: self.assigned[name] = self.find_match(weight, isexit, isguard)
        return self.assigned[name].get_congestion()

class PropagationDelayModel(object):
    """
    """
    def __init__(self, tracefilename):
        pass
