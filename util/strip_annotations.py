import sys
import os
import os.path

if __name__ == '__main__':
    if (len(sys.argv) <= 2):
        print('Usage: strip_annotations [input dir] [output dir]')
        sys.exit(1)
		
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    num_to_print = 0

    for dirpath, dirnames, filenames in os.walk(input_dir):
        for filename in filenames:
            if (filename[0] != '.'):
                out_path = os.path.join(output_dir,os.path.relpath(dirpath,input_dir))
                in_filepath = os.path.join(dirpath,filename)
                out_filepath = os.path.join(out_path,filename)
                if (os.path.isfile(in_filepath)):
                    print('Stripping '+filename+'.')
                    f_in = open(in_filepath,'r')
                    if (not os.path.isdir(out_path)):
                        os.makedirs(out_path)
                    f_out = open(out_filepath,'w')
                    type_count = 0;
                    for line in f_in:
                        # check that first line doesn't start '@type' before writing
                        if (line[0:5] != '@type'):
                            f_out.write(line)
                        elif  (num_to_print > 0):
                            f_out.write(line)
                            num_to_print -= 1
                            type_count += 1
                        else:
                            type_count += 1
                            f_out.write('@downloaded-at 2012-09-17 17:44:50\n')
                            f_out.write('@source "193.28.228.70"\n')
                    print('{0} type count: {1}\n'.format(filename,type_count))
                    f_in.close()
                    f_out.close()