#!/usr/bin/env bash

INPUT_FILE=ndn-1pkt-EM-461B-data-correct-checksum.pcap
OUTPUT_FILE=merged.pcap

for (( i=1; i <= 254; i++ ))
do
    for (( j=1; j <= 254; j++ ))
    do
        tcprewrite --pnat=1.2.3.4/32:5.6.${i}.${j}/32 --infile=${INPUT_FILE} --outfile=output.${i}.${j}.pcap
        mergecap -w ${OUTPUT_FILE} ${OUTPUT_FILE} output.${i}.${j}.pcap
        rm output.${i}.${j}.pcap
    done
done