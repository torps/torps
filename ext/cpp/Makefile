TARGET = safest_ext
TARGET_DIR = $(shell pwd)/
export TARGET_DIR
LIBS = ../message_spec/protobuf-2.5.0/src/.libs/libprotobuf.a
CMD_SRC = cmdline.cc main.cc
SRC = message_spec.pb.cc safest_ext.cc container.c  tor_stubs.c vivaldinode.c $(CMD_SRC)
CC = g++ -I.
CXXFLAGS = -std=c++0x 
CPPFLAGS = -I. -g -Wall -pg -I../message_spec/protobuf-2.5.0/src/ #-O2
LDFLAGS = -pg -g -stdlib=libc++ -lz -Wall
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
	$(CXX) $(LDFLAGS) $(LIBS) $(C_OBJECTS) $(OBJECTS)
	#glibtool --tag=CXX --mode=link $(CXX) -O2 -pg -g -O -o $@ $(LIBS) $(C_OBJECTS) $(OBJECTS) -Wall

clean:
	-rm -f *.o
	-rm -f $(TARGET)              


