#!/bin/bash
cd drivers && ./driver.sh && cd .. && make clean && make test6 && time ./test6
