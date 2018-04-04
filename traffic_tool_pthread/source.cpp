#include <stdio.h>
#include <stdlib.h>
#include "BaseTool.h"
#include <inaddr.h>
#include <string.h>
#if 0
int main()
{
	BaseTool pkt("C:\\Users\\dell\\Documents\\detect_nat\\pcaps\\os\\centos.pcap");
	char * ip = "118.190.80.87";
	auto prst = pkt.cluster_raw_pakcets();
	auto statics_feature = pkt.abstract_statics_feature(prst, inet_addr(ip),60*12,0x02);
	for (int i = 0; i < statics_feature.size(); i++)
	{
		statics_feature[i].display();
	}
	in_addr addr;
	vector< vector<_tcp_srcport_build>> srcport_sequences;
	for (map < unsigned int, vector< _packet_chunk_> > ::iterator it = prst->begin(); it != prst->end(); it++)
	{
		if (it->first != inet_addr(ip))
		{
			continue;
		}
		vector<_tcp_srcport_build> tcp_srcport_data = pkt.get_tcp_srcport_data(prst, it->first);
		auto srcport_sequences_ = pkt.construct_tcpsrcport_sequences(tcp_srcport_data);
		
		if (srcport_sequences_.size())
		{
			srcport_sequences = srcport_sequences_;
			addr.S_un.S_addr = it->first;
			printf("%s : srcport size:%d \n", inet_ntoa(addr), srcport_sequences.size());
		}
	}
	/*system("pause");
	return 0;*/
	//for (int i = 0; i < srcport_sequences.size(); i++)
	//{
	//	printf("NUM(%d):\n", i);
	//	for (int j = 0; j < srcport_sequences[i].size(); j++)
	//	{
	//		printf("%d(%d)  ", srcport_sequences[i][j].srcport, srcport_sequences[i][j].timestamp);
	//		if (j == (srcport_sequences[i].size() - 1))
	//		{
	//			printf("\n");
	//		}
	//	}
	//}
	char *filename = "centos_data.file";
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
#endif