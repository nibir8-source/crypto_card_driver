#!/bin/bash
cd drivers && ./script.sh && cd .. && make clean && make && ./mmap_interrupt
