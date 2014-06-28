import sys
import re

def expect_hour_advance(line, hour, new_hour):
    if (new_hour - hour != 1):
        print('Unexpected hour in {0} old hour: {1}'.format(line, hour))

def expect_day_advance(line, hour, day, new_hour, new_day):
    if (new_hour != 0):
        print('Unexpected hour in {0} old hour: {1}'.format(line, hour))
    if (new_day - day != 1):
        print('Unexpected day in {0} old day: {1}'.format(line[:-1], day))
        
def expect_month_advance(line, hour, day, month, new_hour, new_day, new_month):
    if (new_hour != 0):
        print('Unexpected hour in {0} old hour: {1}'.format(line[:-1], hour))
    if (new_day != 1):
        print('Unexpected day in {0} old day: {1}'.format(line[:-1], day))                            
    if (new_month - month != 1):
        print('Unexpected month in {0} old month: {1}'.format(line[:-1], month))


if __name__ == '__main__':
    usage = 'Usage: examine_process_output.py [filename] [start_month]'
    if (len(sys.argv) < 3):
        print(usage)
        sys.exit(1)
        
    filename = sys.argv[1]
    start_month = int(sys.argv[2])
    
    # per descriptor archive
        # min descriptors read
        # min relays discovered
        # num consensuses
    desc_re = re.compile('#descriptors: ([0-9]*); #relays:([0-9]*)')
    num_cons_re = re.compile('consensuses: ([0-9]*)')
    
    # per consensus
    #Processing consensus file 2012-03-01-07-00-00-consensus
    new_cons_re = re.compile('Processing consensus file 20[0-9]{2}-([0-9]{2})-([0-9]{2})-([0-9]{2})-00-00-consensus')

    # how many were hibernating
    # SteinGate01:365C462E240FFC3D96B2DC70C71C87E7547C9C88 was hibernating at consenses period start
    was_hibern_re = re.compile('was hibernating at consenses period start')
    
    # hibernating starts
    # SunnySmile:2392D8FA5B9C4163C795EE78914194EEB7164A1C started hibernating at 1330588097
    hibern_start_re = re.compile('started hibernating at')
    
    # hibernating stops
    # gedankenverbrechen:5D931C60A73665FFD9C5695C0BB26C18B8B14C6F stopped hibernating at 1330576022
    hibern_stop_re = re.compile('stopped hibernating at')
    
    # min relays with descriptors
    # Wrote descriptors for 2885 relays.
    cons_relays_re = re.compile('Wrote descriptors for ([0-9]*) relays')
    
    # missing descriptors
    missing_desc_re = re.compile('Did not find descriptors for ([0-9]*) relays')

    num_descriptors = []
    num_relays = []
    num_cons = []
    num_was_hibern = []
    num_hibern_start = []
    num_hibern_stop = []
    num_relays_cons = []
    num_relay_cons_after_first_day = []
    num_missing_descriptors = []
    num_missing_descriptors_after_first_day = []
    
    num_was_hibern_cons = 0
    num_hibern_start_cons = 0
    num_hibern_stop_cons = 0
    month = None
    day = None
    hour = None
    
    with open(filename, 'r') as f:
        init = True
        for line in f:
            match = desc_re.search(line)
            if match:
                num_descriptors.append(int(match.group(1)))
                num_relays.append(int(match.group(2)))
                continue
            match = num_cons_re.search(line)
            if match:
                num_cons.append(int(match.group(1)))
                continue
            match = new_cons_re.search(line)
            if match:
                if (init):
                    init = False
                    month = int(match.group(1))
                    day = int(match.group(2))
                    hour = int(match.group(3))
                else:
                    num_was_hibern.append(num_was_hibern_cons)
                    num_was_hibern_cons = 0
                    num_hibern_start.append(num_hibern_start_cons)
                    num_hibern_start_cons = 0
                    num_hibern_stop.append(num_hibern_stop_cons)
                    num_hibern_stop_cons = 0
                    
                    new_month = int(match.group(1))
                    new_day = int(match.group(2))
                    new_hour = int(match.group(3))
                    if (hour < 23):
                        expect_hour_advance(line, hour, new_hour)
                    elif (hour == 23) and\
                        (month not in [2, 4, 6, 9, 11]) and\
                        (day < 31):
                        expect_day_advance(line, hour, day, new_hour, new_day)
                    elif (hour == 23) and\
                        (month not in [2, 4, 6, 9, 11]) and\
                        (day == 31):
                        expect_month_advance(line, hour, day, month, new_hour, new_day, new_month)
                    elif (hour == 23) and\
                        (month in [4, 6, 9, 11]) and\
                        (day < 30):
                        expect_day_advance(line, hour, day, new_hour, new_day)
                    elif (hour == 23) and\
                        (month in [4, 6, 9, 11]) and\
                        (day == 30):
                        expect_month_advance(line, hour, day, month, new_hour, new_day, new_month)
                    elif (hour == 23) and\
                        (month == 2) and\
                        (day < 29):
                        expect_day_advance(line, hour, day, new_hour, new_day)
                    elif (hour == 23) and\
                        (month == 2) and\
                        (day == 29):
                        expect_month_advance(line, hour, day, month, new_hour, new_day, new_month)
                            
                    month = new_month
                    day = new_day
                    hour = new_hour
                continue
            match = was_hibern_re.search(line)
            if match:
                num_was_hibern_cons += 1
                continue
            match = hibern_start_re.search(line)
            if match:
                num_hibern_start_cons += 1
                continue
            match = hibern_stop_re.search(line)
            if match:
                num_hibern_stop_cons += 1
                continue   
            match = cons_relays_re.search(line)
            if match:
                num_relays_cons.append(int(match.group(1)))
                if (month != start_month) or (day != 1):
                    num_relay_cons_after_first_day.append(int(match.group(1)))
                continue
            match = missing_desc_re.search(line)
            if match:
                nmd = int(match.group(1))
                num_missing_descriptors.append(nmd)
                if (month != start_month) or (day != 1):
                    num_missing_descriptors_after_first_day.append(nmd)
                continue
    print('descriptors in desc archive: {0}'.format(num_descriptors))
    print('relays in desc archive: {0}'.format(num_relays))
    print('consensuses in month: {0}'.format(num_cons))
    if num_was_hibern:
        print('max "was hibernating": {0}'.format(max(num_was_hibern)))
    if num_hibern_start:
        print('max "started hibernating": {0}'.format(max(num_hibern_start)))
    if num_hibern_stop:
        print('max "stopped hibernating": {0}'.format(max(num_hibern_stop)))
    if num_relays_cons:    
        print('min relays w/ desc in cons: {0}'.format(min(num_relays_cons)))
    print('min relays w/ desc in cons after first day: {0}'.format(min(num_relay_cons_after_first_day)))
    print('max num missing descriptors: {0}'.format(max(num_missing_descriptors)))
    print('max num missing descriptors after first day: {0}'.format(max(num_missing_descriptors_after_first_day)))