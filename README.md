# detect_nat
A project which can detect nat traffic.
本项目用于发现NAT设备，以及NAT设备后主机数目。其中发现NAT设备使用基于流量的统计特征的一个CNN分类器，而发现NAT主机规模主要使用TCP SYN报文中的src port的序列数来计算
