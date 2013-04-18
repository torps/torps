#!/bin/bash

SCRIPT_DIR="$( dirname "${BASH_SOURCE[0]}" )"
CPP_ENGINE="$SCRIPT_DIR/cpp/safest_ext"
CPP_ENGINE_ARGS="-p 7000"

# Start the C++ engine

if [[ ! -x $CPP_ENGINE ]]; then
  make -C ${SCRIPT_DIR}/cpp clean safest_ext
fi

if [[ ! -x $CPP_ENGINE ]]; then 
  echo "Cannot find C++ engine to execute at '$CPP_ENGINE'" 
  exit 1
fi

echo "Starting $CPP_ENGINE "
$CPP_ENGINE $CPP_ENGINE_ARGS >/tmp/example.engine.out 2>/tmp/example.engine.err &
engine_pid=$!

# Run example.py 
python $SCRIPT_DIR/setup.py develop
python $SCRIPT_DIR/example.py

echo "Killing engine [$engine_pid]"
kill -9 $engine_pid
