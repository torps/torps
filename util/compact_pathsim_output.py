import fileinput

if __name__ == '__main__':
    """Convert the 'normal' pathsim format to the 'relay-adv' format."""

    bad_guard_ip = '10.1.0.0'
    bad_exit_ip = '10.2.0.0'
    print('Sample\tTimestamp\tCompromise Code')
    for line in fileinput.input():
        # advance past header
        if (line[0:6] == 'Sample'):
            continue
        fields = line.split()
        sample_id = fields[0]
        timestamp = fields[1]
        guard_ip = fields[2]
        exit_ip = fields[4]
        guard_bad = False
        exit_bad = False
        if (guard_ip == bad_guard_ip) or (guard_ip == bad_exit_ip):
            guard_bad = True
        if (exit_ip == bad_guard_ip) or (exit_ip == bad_exit_ip):
            exit_bad = True
        if (guard_bad and exit_bad):
            compromise_code = 3
        elif guard_bad:
            compromise_code = 1
        elif exit_bad:
            compromise_code = 2
        else:
            compromise_code = 0        
        print('{0}\t{1}\t{2}'.format(sample_id, timestamp,
            compromise_code))