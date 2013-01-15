import sys
import os
import os.path

if __name__ == '__main__':
    if (len(sys.argv) <= 2):
        print('Usage: strip_annotations [input dir] [output dir]')
        sys.exit(1)
		
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]

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
                        else:
                            type_count += 1
                    print('{0} type count: {1}\n'.format(filename,type_count))
                    f_in.close()
                    f_out.close()