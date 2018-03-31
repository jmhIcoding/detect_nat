#!/bin/bash

#echo 'active nat-device-flow-feature gathering' \
setsid vectorize_online 114_242_164_187.dat 114.242.164.187 nat 720 p4p1 \
& setsid vectorize_online 114_242_164_186.dat 114.242.164.186 nat 720 p4p1 \
& setsid vectorize_online 172_16_30_29.dat 172.16.30.29 nat 720 p4p1 \
& setsid vectorize_online 172_16_30_159.dat 172.16.30.159 nat 720 p4p1 \
& setsid vectorize_online 172_16_30_34.dat 172.16.30.34 host 720 p4p1 \
& setsid vectorize_online 172_16_30_42.dat 172.16.30.42 host 720 p4p1 \
& setsid vectorize_online 172_16_30_43.dat 172.16.30.43 host 720 p4p1 \
& setsid vectorize_online 172_16_30_45.dat 172.16.30.45 host 720 p4p1 \
& setsid vectorize_online 172_16_30_47.dat 172.16.30.47 host 720 p4p1 \
& setsid vectorize_online 172_16_30_49.dat 172.16.30.49 host 720 p4p1 \
& setsid vectorize_online 172_16_30_50.dat 172.16.30.50 host 720 p4p1 \
& setsid vectorize_online 172_16_30_146.dat 172.16.30.146 host 720 p4p1 \
& setsid vectorize_online 172_16_30_151.dat 172.16.30.151 host 720 p4p1 \
& setsid vectorize_online 172_16_30_152.dat 172.16.30.152 host 720 p4p1 \
& setsid vectorize_online 172_16_30_159.dat 172.16.30.159 host 720 p4p1 \
& setsid vectorize_online 172_16_30_170.dat 172.16.30.170 host 720 p4p1 \
