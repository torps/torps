TARGET = safest_ext
TARGET_DIR = $(shell pwd)/
export TARGET_DIR
LIBS = ../message_spec/protobuf-2.5.0/src/libprotobuf.la -lstdc++
CMD_SRC = cmdline.cc main.cc
SRC = message_spec.pb.cc safest_ext.cc container.c  tor_stubs.c vivaldinode.c $(CMD_SRC)
CC = g++ -I.
CPPFLAGS = -g -Wall -pg -I../message_spec/protobuf-2.5.0/src/ -O2 #-std=c++0x -O2
PROD_CFLAGS = $(CFLAGS) -O2 #-std=c++0x 
TESTDIR = test

.PHONY: default all clean cmdline message_spec.pb.cc

default: $(TARGET)
all: default

cmdline.cc: opts.ggo
	gengetopt -c cc < opts.ggo

message_spec.pb.cc:
	$(MAKE) -C $(TARGET_DIR)../message_spec/ cpp

C_OBJECTS = $(patsubst %.c, %.o, $(filter %.c, $(SRC)))
OBJECTS = $(patsubst %.cc, %.o, $(filter %.cc, $(SRC)))
HEADERS = $(wildcard *.h)

%.o: %.cc %.c
	$(CC) $(CFLAGS) -c $< -o $@
#ifeq "$(suffix $<)" ".cc"
#else
	#gcc $(CFLAGS) -c $< -o $@
#endif

.PRECIOUS: $(TARGET) $(OBJECTS) $(C_OBJECTS) message_spec.pb.cc

$(TARGET): $(CMD_SRC)  $(OBJECTS) $(C_OBJECTS) 
	glibtool --tag=CXX --mode=link gcc -O2 -pg -g -O -o $@ $(LIBS) $(C_OBJECTS) $(OBJECTS) -Wall

production: $(CMD_SRC) $(OBJECTS)
	$(CC) $(PROD_CFLAGS) -c $(CMD_SRC)
	$(CC) $(PROD_CFLAGS) $(LIBS) $(OBJECTS) $(patsubst %.cc, %.o, $(CMD_SRC)) -Wall -o $(TARGET)


clean:
	-rm -f *.o
	-rm -f $(TARGET)              


