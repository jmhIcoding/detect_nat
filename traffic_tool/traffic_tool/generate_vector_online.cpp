#include <stdio.h>
#include <stdlib.h>
#include "BaseTool.h"
#include <inaddr.h>
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
#if 1
int main(int argc, char *argv[])
{
	if (argc != 6)
	{
		printf("usage:\
			   			   				%s outfile(**.dat) ip_addr(172.16.30.29) device_type(nat or host) timegap(720) interface(eth2.2) \n", argv[0]);
#ifdef WINDOWS
		system("pause");
#endif
		exit(-1);
	}
	char * ip = argv[2];
	char device_type = 0x01; //host
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
		auto prst = pkt.cluster_raw_pakcets_online(0,timegap);
		auto statics_feature = pkt.abstract_statics_feature(prst, inet_addr(ip), timegap, device_type);
		for (int i = 0; i < statics_feature.size(); i++)
		{
			statics_feature[i].vectorize(fp);
			count++;
		}
		if (count % 20==0)
		{
			fflush(fp);
		}

	}
	fclose(fp);
}
#endif