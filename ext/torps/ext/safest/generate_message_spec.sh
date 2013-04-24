#/bin/bash

cd "$( dirname "${BASH_SOURCE[0]}" )"

TARGET_DIR=$(pwd) make -C ../message_spec/ python

mv message_spec_pb2.py protobuf.py

