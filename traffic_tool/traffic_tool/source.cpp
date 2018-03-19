#include <stdio.h>
#include <stdlib.h>
#include "BaseTool.h"
#include <inaddr.h>
#include <string.h>
int main()
{
	BaseTool pkt("C:\\Users\\dell\\Documents\\detect_nat\\pcaps\\03_13_12_30_14_10_172_16_30_34_windows_7.pcap");
	auto prst = pkt.cluster_raw_pakcets();
	for (map < unsigned int, vector< _packet_chunk_>> ::iterator p = prst->begin(); p != prst->end(); p++)
	{
		in_addr addr;
		addr.S_un.S_addr =(unsigned int (p->first));
		printf("%0.16s (%X) packets:%d \n",inet_ntoa(addr),p->first,(p->second).size());
	}
	vector<_ipid_build> ipid_data = pkt.get_ipid_data(prst, inet_addr("172.16.30.34"));
	vector< vector<_ipid_build> > ipid_sequences = pkt.construct_ipid_sequences(ipid_data);
	char *filename = "data.file";
	FILE *fp = fopen(filename, "w");

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
	vector<_tcp_sequence_build> tcp_seq_data = pkt.get_tcp_seq_data(prst, inet_addr("172.16.30.34"));
	vector< vector<_tcp_sequence_build>> tcp_seq_sequences = pkt.construct_tcp_sequences(tcp_seq_data);
	vector< vector<int>> associate_ipid_seq = pkt.associate_ipidseq_tcpseqs(ipid_sequences, tcp_seq_sequences);
	vector<_tcp_srcport_build> tcp_srcport_data = pkt.get_tcp_srcport_data(prst, inet_addr("172.16.30.34"));
	auto srcport_sequences = pkt.construct_tcpsrcport_sequences(tcp_srcport_data);
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