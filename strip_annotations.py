import sys
import os

if __name__ == '__main__':
	if (len(sys.argv) <= 2):
		print('Usage: strip_annotations [input dir] [output dir]')
		sys.exit(1)
		
	input_dir = sys.argv[1]
	output_dir = sys.argv[2]

	for filename in os.listdir(input_dir):
	    # for each file in that directory
	    filepath = os.path.join(input_dir,filename)
	    if (os.path.isfile(filepath)):
	    	print('Stripping '+filename+'.')
	    	f_in = open(filepath,'r')
	    	f_out = open(os.path.join(output_dir,filename),'w')
	    	type_count = 0;
	    	for line in f_in:
#		    	# check that first line doesn't start '@type' before writing
	    		if (line[0:5] != '@type'):
	    			f_out.write(line)
	    		else:
	    			type_count += 1
	    	print('Type count: {0}\n'.format(type_count))
	    	f_in.close()
	    	f_out.close()