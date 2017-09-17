#!/bin/bash

export LD_LIBRARY_PATH=/usr/local/pgsql/lib64/

./bin/Release/dpi $1 $2
