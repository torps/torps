### Classes implementing "network modification" interface, i.e. modify_network_state() ###

from stem import Flag
from stem.exit_policy import ExitPolicy
import pathsim

class Enum(tuple): __getattr__ = tuple.index

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
            self.adv_relays[fingerprint] = pathsim.RouterStatusEntry(fingerprint,
                nickname, flags, bandwidth)
            
            # create descriptor
            hibernating = False
            family = {}
            address = '10.'+num_str+'.0.0' # avoid /16 conflicts
            exit_policy = ExitPolicy('reject *:*')
            ntor_onion_key = num_str # indicate ntor support w/ val != None
            self.adv_descriptors[fingerprint] = pathsim.ServerDescriptor(fingerprint,
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
            self.adv_relays[fingerprint] = pathsim.RouterStatusEntry(fingerprint,
                nickname, flags, bandwidth)
            
            # create descriptor
            hibernating = False
            family = {}
            address = '10.'+str(num_adv_guards+i+1)+'.0.0' # avoid /16 conflicts
            exit_policy = ExitPolicy('accept *:*')
            ntor_onion_key = num_str # indicate ntor support w/ val != None
            self.adv_descriptors[fingerprint] = pathsim.ServerDescriptor(fingerprint,
                hibernating, nickname, family, address, exit_policy,
                ntor_onion_key)

    def compute_tot_bandwidths(self, cons_rel_stats, descriptors):
        """ Compute 
        G the total bandwidth for Guard-flagged nodes
        M the total bandwidth for non-flagged nodes
        E the total bandwidth for Exit-flagged nodes
        D the total bandwidth for Guard+Exit-flagged nodes
        T = G+M+E+D
        """
        
        def filter_flags(cons_rel_stats, descriptors, flags, no_flags):
            nodes  = []
            for fprint in cons_rel_stats:
                rel_stat = cons_rel_stats[fprint]
                i = 0
                j = 0
                for flag in no_flags:
                    if flag in rel_stat.flags:
                        j+=1
                for flag in flags:
                    if flag in rel_stat.flags:
                        i+=1
                if i == len(flags) and j==0 and fprint in descriptors:
                    nodes.append(fprint)
            return nodes

        guards = filter_flags(cons_rel_stats, descriptors,\
                    [Flag.RUNNING, Flag.VALID, Flag.GUARD], [Flag.EXIT])
        exits = filter_flags(cons_rel_stats, descriptors,\
                    [Flag.RUNNING, Flag.VALID, Flag.EXIT], [Flag.GUARD])
        middles = filter_flags(cons_rel_stats, descriptors,\
                    [Flag.RUNNING, Flag.VALID], [Flag.GUARD, Flag.EXIT])
        guards_exits = filter_flags(cons_rel_stats, descriptors,\
                        [Flag.RUNNING, Flag.VALID, Flag.GUARD, Flag.EXIT], [])
        G = M = E = D = T = 0
        
        for fprint in guards:
            G += cons_rel_stats[fprint].bandwidth
        for fprint in middles:
            M += cons_rel_stats[fprint].bandwidth
        for fprint in exits:
            E += cons_rel_stats[fprint].bandwidth
        for fprint in guards_exits:
            D += cons_rel_stats[fprint].bandwidth

        T = G+M+E+D
        return (int(G), int(M), int(E), int(D), int(T))

    def check_weights_errors(self, Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed,
            weightscale, G, M, E, D, T, margin, do_balance):

        """Verify that our weights satify the formulas from dir-spec.txt"""

        def check_eq(a, b, margin):
            return (a - b) <= margin if (a - b) >= 0 else (b - a) <= margin
        def check_range(a, b, c, d, e, f, g, mx):
            return (a >= 0 and a <= mx and b >= 0 and b <= mx and\
                    c >= 0 and c <= mx and d >= 0 and d <= mx and\
                    e >= 0 and e <= mx and f >= 0 and f <= mx and\
                    g >= 0 and g <= mx)

        # Wed + Wmd + Wgd == weightscale
        if (not check_eq(Wed+Wmd+Wgd, weightscale, margin)):
            return self.bww_errors.SUMD_ERROR
        # Wmg + Wgg == weightscale
        if (not check_eq(Wmg+Wgg, weightscale, margin)):
            return self.bww_errors.SUMG_ERROR
        # Wme + Wee == 1
        if (not check_eq(Wme+Wee, weightscale, margin)):
            return self.bww_errors.SUME_ERROR
        # Verify weights within range 0 -> weightscale
        if (not check_range(Wgg, Wgd, Wmg, Wme, Wmd, Wed, Wee, weightscale)):
            return self.bww_errors.RANGE_ERROR
        if (do_balance):
            #Wgg*G + Wgd*D == Wee*E + Wed*D
            if (not check_eq(Wgg*G+Wgd*D, Wee*E+Wed*D, (margin*T)/3)):
                return self.bww_errors.BALANCE_EG_ERROR
            #Wgg*G+Wgd*D == M*weightscale + Wmd*D + Wme * E + Wmg*G
            if (not check_eq(Wgg*G+Wgd*D, M*weightscale+Wmd*D+Wme*E+Wmg*G,\
                    (margin*T)/3)):
                return self.bww_errors.BALANCE_MID_ERROR


        return self.bww_errors.NO_ERROR


    def __init__(self, args, testing):
        self.adv_time = args.adv_time
        self.adv_relays = {}
        self.adv_descriptors = {}
        self.add_adv_guards(args.num_adv_guards, args.adv_guard_cons_bw)
        self.add_adv_exits(args.num_adv_guards, args.num_adv_exits,
            args.adv_exit_cons_bw)
        self.testing = testing
        self.first_modification = True
        self.bww_errors = Enum(("NO_ERROR","SUMG_ERROR", "SUME_ERROR",\
                "SUMD_ERROR","BALANCE_MID_ERROR", "BALANCE_EG_ERROR",\
                "RANGE_ERROR"))

        
    def modify_network_state(self, network_state):
        """Adds adversarial guards and exits to cons_rel_stats and
        descriptors dicts."""

        # add adversarial descriptors to nsf descriptors
        # only add once because descriptors variable is assumed persistant
        if (self.first_modification == True):
            network_state.descriptors.update(self.adv_descriptors)
            self.first_modification = False

        # if insertion time has been reached, add adversarial relays into
        # consensus and hibernating status list
        if (self.adv_time <= network_state.cons_valid_after):
            # include additional relays in consensus
            if self.testing:
                print('Adding {0} relays to consensus.'.format(\
                    len(self.adv_relays)))
            for fprint, relay in self.adv_relays.iteritems():
                if fprint in network_state.cons_rel_stats:
                    raise ValueError(\
                        'Added relay exists in consensus: {0}:{1}'.\
                            format(relay.nickname, fprint))
                network_state.cons_rel_stats[fprint] = relay
            # include hibernating statuses for added relays
            network_state.hibernating_statuses.extend([(0, fp, False) \
                for fp in self.adv_relays])
            # recompute bwweights taking into account the new nodes added
            (casename, Wgg, Wgd, Wee, Wed, Wmg, Wme, Wmd) =\
                    self.recompute_bwweights(network_state)
            bwweights = network_state.cons_bw_weights
            if self.testing: 
                print("""New computation of bwweights, network load case
                       is {0} with weights Wgg={1}, Wgd={2}, Wee={3},
                       Wed={4}, Wmg={5}, Wme={6}, Wmd={7}.\n
                       The weights received from the consensus are Wgg=
                       {8}, Wgd={9}, Wee={10}, Wed={11}, Wmg={12}, Wme=
                       {13}, Wmd={14} """.format(casename, Wgg, Wgd, Wee,\
                       Wed, Wmg, Wme, Wmd, bwweights['Wgg'], bwweights['Wgd'],\
                       bwweights['Wee'], bwweights['Wed'], bwweights['Wmg'],\
                       bwweights['Wme'], bwweights['Wmd']))
            bwweights['Wgg'] = Wgg
            bwweights['Wgd'] = Wgd
            bwweights['Wee'] = Wee
            bwweights['Wed'] = Wed
            bwweights['Wmg'] = Wmg
            bwweights['Wme'] = Wme
            bwweights['Wmd'] = Wmd

    def recompute_bwweights(self, network_state):
        """Detects in which network case load we are according to section 3.8.3
        of dir-spec.txt from Tor' specifications and recompute bandwidth weights
        """
        (G, M, E, D, T) = self.compute_tot_bandwidths(network_state.cons_rel_stats,\
                network_state.descriptors)
        weightscale = network_state.cons_bwweightscale
        if (3*E >= T and 3*G >= T):
            #Case 1: Neither are scarce
            casename = "Case 1 (Wgd=Wmd=Wed)"
            Wgd = Wed = Wmd = weightscale/3
            Wee = (weightscale*(E+G+M))/(3*E)
            Wme = weightscale - Wee
            Wmg = (weightscale*(2*G-E-M))/(3*G)
            Wgg = weightscale - Wmg
            
            check = self.check_weights_errors(Wgg, Wgd, Wmg, Wme, Wmd, Wee, Wed,\
                    weightscale, G, M, E, D, T, 10, True)
            if (check):
                raise ValueError(\
                        'ERROR: {0}  Wgd={1}, Wed={2}, Wmd={3}, Wee={4},\
                         Wmd={4}, Wgg={6}'.format(self.bww_errors[check],\
                         Wgd, Wed, Wmd, Wee, Wmg, Wgg))
        elif (3*E < T and 3*G < T):
            #Case 2: Both Guards and Exits are scarce
            #Balance D between E and G, depending upon D capacity and
            #scarcity
            R = min(E, G)
            S = max(E, G)
            if (R+D < S):
                #subcase a
                Wgg = Wee = weightscale
                Wmg = Wme = Wmd = 0
                if (E < G):
                    casename = "Case 2a (E scarce)"
                    Wed = weightscale
                    Wgd = 0
                else: 
                    # E >= G
                    casename = "Case 2a (G scarce)"
                    Wed = 0
                    Wgd = weightscale

            else:
                #subcase b R+D >= S
                casename = "Case 2b1 (Wgg=weightscale, Wmd=Wgd)"
                Wee = (weightscale*(E-G+M))/E
                Wed = (weightscale*(D-2*E+4*G-2*M))/(3*D)
                Wme = (weightscale*(G-M))/E
                Wmg = 0
                Wgg = weightscale
                Wmd = Wgd = (weightscal-Wed)/2
                
                check = self.check_weights_errors(Wgg, Wgd, Wmg, Wme, Wmd,\
                        Wee, Wed, weightscale, G, M, E, D, T, 10, True)
                if (check):
                    casename = 'Case 2b2 (Wgg=1, Wee=1)'
                    Wgg = Wee = weightscale
                    Wed = (weightscale*(D-2*E+G+M))/(3*D)
                    Wmd = (weightscale*(D-2*M+G+E))/(3*D)
                    Wme = Wmg = 0
                    if (Wmd < 0):
                        #Too much bandwidth at middle position
                        casename = 'case 2b3 (Wmd=0)'
                        Wmd = 0
                    Wgd = weightscale - Wed - Wmd
                    
                    check = self.check_weights_errors(Wgg, Wgd, Wmg, Wme, Wmd,\
                            Wee, Wed, weightscale, G, M, E, D, T, 10, True)
                if (check != self.bww_errors.NO_ERROR and check !=\
                        self.bww_errors.BALANCE_MID_ERROR):
                    raise ValueError(\
                        'ERROR: {0}  Wgd={1}, Wed={2}, Wmd={3}, Wee={4},\
                         Wmd={4}, Wgg={6}'.format(self.bww_errors[check],\
                         Wgd, Wed, Wmd, Wee, Wmg, Wgg))
        else: # if (E < T/3 or G < T/3)
            #Case 3: Guard or Exit is scarce
            S = min(E, G)

            if (not (3*E < T or  3*G < T) or not (3*G >= T or 3*E >= T)):
                raise ValueError(\
                        'ERROR: Bandwidths have inconsistants values \
                        M={0}, E={1}, D={2}, T={3}'.format(M,E,D,T))

            if (3*(S+D) < T):
                #subcasea: S+D < T/3
                if (G < E):
                    casename = 'Case 3a (G scarce)'
                    Wgg = Wgd = weightscale
                    Wmd = Wed = Wmg = 0
                    
                    if (E < M): Wme = 0
                    else: Wme = (weightscale*(E-M))/(2*E)
                    Wee = weightscale - Wme
                else:
                    # G >= E
                    casename = "Case 3a (E scarce)"
                    Wee = Wed = weightscale
                    Wmd = Wgd = Wme = 0
                    if (G < M): Wmg = 0
                    else: Wmg = (weightscale*(G-M))/(2*G)
                    Wgg = weightscale - Wmg
            else:
                #subcase S+D >= T/3
                if (G < E):
                    casename = """Case 3bg (G scarce, Wgg=weightscale,
                                Wmd == Wed"""
                    Wgg = weightscale
                    Wgd = (weightscale*(D-2*G+E+M))/(3*D)
                    Wmg = 0
                    Wee = (weightscale*(E+M))/(2*E)
                    Wme = weightscale - Wee
                    Wmd = Wed = (weightscale-Wgd)/2

                    check = self.check_weights_errors(Wgg, Wgd, Wmg, Wme,\
                            Wmd, Wee, Wed, weightscale, G, M, E, D, T, 10,\
                            True)
                else:
                    # G >= E
                    casename = """Case 3be (E scarce, Wee=weightscale,
                                Wmd == Wgd"""

                    Wee = weightscale
                    Wed = (weightscale*(D-2*E+G+M))/(3*D)
                    Wme = 0
                    Wgg = (weightscale*(G+M))/(2*G)
                    Wmg = weightscale - Wgg
                    Wmd = Wgd = (weightscale-Wed)/2

                    check = self.check_weights_errors(Wgg, Wgd, Wmg, Wme,\
                            Wmd, Wee, Wed,  weightscale, G, M, E, D, T, 10,\
                            True)


                if (check):
                    raise ValueError(\
                        'ERROR: {0}  Wgd={1}, Wed={2}, Wmd={3}, Wee={4},\
                         Wmd={4}, Wgg={6}'.format(self.bww_errors[check],\
                         Wgd, Wed, Wmd, Wee, Wmg, Wgg))

        return (casename, Wgg, Wgd, Wee, Wed, Wmg, Wme, Wmd)


######

### Class adjusting Guard flags ###
class RaiseGuardConsBWThreshold(object):
    def __init__(self, args, testing):
        # obtain argument string, assumed in form: full_classname:cons_bw_threshold
        full_classname, class_arg = args.other_network_modifier.split('-')
        # interpret arg as consensus weight limit for Guard flag
        self.guard_bw_threshold = int(class_arg)
        self.testing = testing

        
    def modify_network_state(self, network_state):
        """Remove Guard flag when relay doesn't meet consensus bandwidth threshold."""

        num_guard_flags = 0
        num_guard_flags_removed = 0
        for fprint, rel_stat in network_state.cons_rel_stats.iteritems():
            if (Flag.GUARD in rel_stat.flags):
                num_guard_flags += 1
                if (rel_stat.bandwidth < self.guard_bw_threshold):
                    num_guard_flags_removed += 1
                    rel_stat.flags = filter(lambda x: x != Flag.GUARD, rel_stat.flags)
        if self.testing:
            print('Removed {} guard flags out of {}'.format(num_guard_flags_removed,
                num_guard_flags))
######
