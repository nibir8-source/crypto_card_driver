#!/bin/bash
cd drivers && ./driver.sh && cd .. && make clean && make test1 && time ./test1
