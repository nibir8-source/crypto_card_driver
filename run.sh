#!/bin/bash
cd drivers && ./driver.sh && cd .. && make clean && make test7 && time ./test7
