#!/bin/bash
cd drivers && ./script.sh && cd .. && make clean && make && time ./test1
