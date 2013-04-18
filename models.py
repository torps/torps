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
        import cPickle as pickle
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
        import cPickle as pickle
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
        import datetime
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

def get_user_model(start_time, end_time, tracefilename=None, session="simple"):
    streams = []
    if session == "simple":
        # simple user that makes a port 80 request /resolve every x / y seconds
        num_requests = 6
        http_request_wait = int(60 / num_requests) * 60
        str_ip = '74.125.131.105' # www.google.com
        for t in xrange(start_time, end_time, http_request_wait):
            streams.append({'time':t,'type':'connect','ip':str_ip,'port':80})
    else:
        ut = UserTraces.from_pickle(tracefilename)
        um = UserModel(ut, start_time, end_time)
        streams = um.get_streams(session)
    return streams

class CongestionTraces(object):
    """
    """
    def __init__(self):
        pass

class CongestionModel(object):
    """
    """
    def __init__(self):
        pass

def get_congestion_model(tracefilename):
    return

class PropagationDelayModel(object):
    """
    """
    def __init__(self):
        pass

def get_propdelay_model(tracefilename):
    return
