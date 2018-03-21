#include <stdio.h>
#include <stdlib.h>
#include "BaseTool.h"
#include <inaddr.h>
#include <string.h>
int main()
{
	BaseTool pkt("C:\\Users\\dell\\Documents\\detect_nat\\pcaps\\03_21_14_30_15_30_172_16_30_34_windows_7.pcap");
	char * ip = "172.16.30.34";
	auto prst = pkt.cluster_raw_pakcets();
	vector<_tcp_srcport_build> tcp_srcport_data = pkt.get_tcp_srcport_data(prst, inet_addr(ip));
	auto srcport_sequences = pkt.construct_tcpsrcport_sequences(tcp_srcport_data);
	printf("srcport size:%d \n", srcport_sequences.size());
	for (int i = 0; i < srcport_sequences.size(); i++)
	{
		printf("NUM(%d):\n", i);
		for (int j = 0; j < srcport_sequences[i].size(); j++)
		{
			printf("%d(%d)  ", srcport_sequences[i][j].srcport, srcport_sequences[i][j].timestamp);
			if (j == (srcport_sequences[i].size() - 1))
			{
				printf("\n");
			}
		}
	}
	char *filename = "data.file";
	FILE *fp = fopen(filename, "w");

	fprintf(fp, "[");
	for (int i = 0; i < srcport_sequences.size(); i++)
	{
		fprintf(fp, "[");
		for (int j = 0; j <srcport_sequences[i].size(); j++)
		{
			fprintf(fp, "[%d,%d]", srcport_sequences[i][j].srcport, srcport_sequences[i][j].timestamp);
			if (j < (srcport_sequences[i].size() - 1))
			{
				fprintf(fp, ",");
			}
		}
		fprintf(fp, "]");
		if (i < (srcport_sequences.size() - 1))
		{
			fprintf(fp, ",");
		}
	}
	fprintf(fp, "]");

	fclose(fp);
	system("pause");
}