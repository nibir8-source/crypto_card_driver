#!/bin/bash
cd drivers && ./script.sh && cd .. && make clean && make && time ./mmap_interrupt
