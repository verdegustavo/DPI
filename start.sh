#!/bin/bash

export LD_LIBRARY_PATH=/usr/local/pgsql/lib64/

./bin/Release/dpi -c config/DB.cfg -i wlan0 -s 10000
