#include <stdio.h>
#include <stdlib.h>
#include "BaseTool.h"
#include "IPCBase.h"
#include "EntroyEstimation.h"
#include "Controller.h"
#include <inaddr.h>
#include <string.h>
int main()
{
	BaseTool pkt("C:\\Users\\dell\\Documents\\detect_nat\\pcaps\\03_13_09_50_11_00_172_16_30_34_windows_7.pcap");
	char *filename = "data.file";
	FILE *fp = fopen(filename, "w");
	auto rst =pkt.get_host_count_data(NULL, inet_addr("172.16.30.34"));
	vector< vector<_ipid_build> > ipid_sequences = pkt.construct_ipid_sequence(rst);

	printf("size: %d \n", ipid_sequences.size());
	fprintf(fp, "[");
	for (int i = 0; i < ipid_sequences.size(); i++)
	{
		fprintf(fp, "[");
		for (int j = 0; j < ipid_sequences[i].size(); j++)
		{
			fprintf(fp, "[%d,%d]", ipid_sequences[i][j].ipid, ipid_sequences[i][j].timestamp);
			if (j < (ipid_sequences[i].size() - 1))
			{
				fprintf(fp, ",");
			}
		}
		fprintf(fp, "]");
		if (i < (ipid_sequences.size() - 1))
		{
			fprintf(fp, ",");
		}
	}
	fprintf(fp, "]");
	fclose(fp);
	//printf("new ip ");
	//BaseTool pkt2("C:\\Users\\dell\\Documents\\detect_nat\\pcaps\\03_13_08_30_11_31_192_168_8_153_MacOS.pcap");

	//auto rst2 = pkt2.get_host_count_data(NULL, inet_addr("192.168.8.153"));
	//for (int i = 0; i < rst2.size(); i++)
	//{
	//	printf("%d:%x  ", rst2[i].ipid,(long)rst2[i].tcpseq);
	//	//if (i<(rst2.size() - 1) && (rst2[i + 1].ipid - rst2[i].ipid)>2)
	//	//{
	//	//	printf("\n\n new ip id sequence   \n");
	//	//}
	//}
	system("pause");
}