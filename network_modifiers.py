### Classes implementing "network modification" interface, i.e. modify_network_state() ###

### Class inserting adversary relays ###
class AdversaryInsertion(object):
    def add_adv_guards(self, num_adv_guards, bandwidth):
        """"Adds adv guards into self.add_relays and self.add_descriptors."""
        #, adv_relays, adv_descriptors
        for i in xrange(num_adv_guards):
            # create consensus
            num_str = str(i+1)
            fingerprint = '0' * (40-len(num_str)) + num_str
            nickname = 'BadGuyGuard' + num_str
            flags = [Flag.FAST, Flag.GUARD, Flag.RUNNING, Flag.STABLE,
                Flag.VALID]
            self.adv_relays[fingerprint] = RouterStatusEntry(fingerprint,
                nickname, flags, bandwidth)
            
            # create descriptor
            hibernating = False
            family = {}
            address = '10.'+num_str+'.0.0' # avoid /16 conflicts
            exit_policy = ExitPolicy('reject *:*')
            ntor_onion_key = num_str # indicate ntor support w/ val != None
            self.adv_descriptors[fingerprint] = ServerDescriptor(fingerprint,
                hibernating, nickname, family, address, exit_policy,
                ntor_onion_key)


    def add_adv_exits(self, num_adv_guards, num_adv_exits, bandwidth):
        """"Adds adv exits into self.add_relays and self.add_descriptors."""
        for i in xrange(num_adv_exits):
            # create consensus
            num_str = str(i+1)
            fingerprint = 'F' * (40-len(num_str)) + num_str
            nickname = 'BadGuyExit' + num_str
            flags = [Flag.FAST, Flag.EXIT, Flag.RUNNING, Flag.STABLE,
                Flag.VALID]
            self.adv_relays[fingerprint] = RouterStatusEntry(fingerprint,
                nickname, flags, bandwidth)
            
            # create descriptor
            hibernating = False
            family = {}
            address = '10.'+str(num_adv_guards+i+1)+'.0.0' # avoid /16 conflicts
            exit_policy = ExitPolicy('accept *:*')
            ntor_onion_key = num_str # indicate ntor support w/ val != None
            self.adv_descriptors[fingerprint] = ServerDescriptor(fingerprint,
                hibernating, nickname, family, address, exit_policy,
                ntor_onion_key)


    def __init__(self, args, testing):
        self.adv_time = args.adv_time
        self.adv_relays = {}
        self.adv_descriptors = {}
        self.add_adv_guards(args.num_adv_guards, args.adv_guard_cons_bw)
        self.add_adv_exits(args.num_adv_guards, args.num_adv_exits,
            args.adv_exit_cons_bw)
        self.testing = testing
        self.first_modification = True

        
    def modify_network_state(self, cons_valid_after, cons_fresh_until,
        cons_bw_weights, cons_bwweightscale, cons_rel_stats, descriptors,
        hibernating_statuses):
        """Adds adversarial guards and exits to cons_rel_stats and
        descriptors dicts."""

        # add adversarial descriptors to nsf descriptors
        # only add once because descriptors variable is assumed persistant
        if (self.first_modification == True):
            descriptors.update(self.adv_descriptors)
            self.first_modification = False

        # if insertion time has been reached, add adversarial relays into
        # consensus and hibernating status list
        if (self.adv_time <= cons_valid_after):
            # include additional relays in consensus
            if self.testing:
                print('Adding {0} relays to consensus.'.format(\
                    len(self.adv_relays)))
            for fprint, relay in self.adv_relays.iteritems():
                if fprint in cons_rel_stats:
                    raise ValueError(\
                        'Added relay exists in consensus: {0}:{1}'.\
                            format(relay.nickname, fprint))
                cons_rel_stats[fprint] = relay
            # include hibernating statuses for added relays
            hibernating_statuses.extend([(0, fp, False) \
                for fp in self.adv_relays])
######