#include <stdio.h>
#include <stdlib.h>
#include "BaseTool.h"
#ifdef _WIN32
#include <inaddr.h>
#endif
#ifdef __linux__
#include <arpa/inet.h>
#endif
#include <string.h>
int str2int(char *str)
{
	int rst = 0;
	for (int i = 0; i<strlen(str); i++)
	{
		rst = rst * 10 + str[i] - '0';
	}
	return rst;
}
#if 0
int main(int argc, char *argv[])
{
	for (int i = 0; i < argc; i++)
	{
		printf("%s\n", argv[i]);
	}
	if (argc != 6)
	{
		printf("usage:\n%s outfile(**.dat) ip_addr(172.16.30.29) device_type(nat or host) timegap(720) interface(eth2.2) \n", argv[0]);
#ifdef _WIN32
		system("pause");
#endif
		exit(-1);
	}
	char * ip = argv[2];
	char device_type = 0x00; //host
	int timegap=str2int(argv[4]);
	char filter[256] = { 0 };
	sprintf(filter, "host %s ", ip);
	BaseTool pkt(argv[5], filter);
	char buf[1024] = { 0 };
	char *filename = argv[1];
	FILE *fp = fopen(filename, "a");
	if (fp == NULL)
	{
		printf("open %s error.\n", filename);
#ifdef WINDOWS
		system("pause");
#endif
		exit(-1);
	}
	if (strcmp(argv[3], "nat") == 0)
	{
		device_type = 0x02;
	}
	else if (strcmp(argv[3], "host") == 0)
	{
		device_type = 0x01;
	}
	else
	{
		printf("device_type reject.\n");
#ifdef WINDOWS
		system("pause");
#endif
		exit(-1);
	}
	int count = 0;
	while (true)
	{
		map<unsigned int,vector< _packet_chunk_> > * prst = pkt.cluster_raw_pakcets_online(0,timegap);
		vector<_packet_statics_feature> statics_feature = pkt.abstract_statics_feature(prst, inet_addr(ip), timegap, device_type);
		for (int i = 0; i < statics_feature.size(); i++)
		{
			statics_feature[i].vectorize(fp);
			count++;
		}
		if (count % 5==0)
		{
			fflush(fp);
		}

	}
	fclose(fp);
}
#endif
