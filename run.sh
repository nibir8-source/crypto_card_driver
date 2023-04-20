#!/bin/bash
cd drivers && ./driver.sh && cd .. && make clean && make && time ./mmap_interrupt
