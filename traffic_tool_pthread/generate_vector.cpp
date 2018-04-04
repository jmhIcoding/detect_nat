#include <stdio.h>
#include <stdlib.h>
#include "BaseTool.h"
#include <inaddr.h>
#include <string.h>
#if 1
int main()
{
	BaseTool pkt("D:\\nat_host_pcap\\pcaps\\nat_netflow\\0328\\lan_03_28.pcap");
	char * ip = "192.168.199.153";
	char filter[256] = { 0 };
	sprintf(filter, "host %s ", ip);
	pkt.setFilter(filter);
	char device_type = 0x01;//02 nat;01 host
	auto prst = pkt.cluster_raw_pakcets();
	auto statics_feature = pkt.abstract_statics_feature(prst, inet_addr(ip), 60 * 12, device_type);
	char buffer[512];
	char * filename = ".\\data\\vectorize_data_03_29.dat";
	FILE *fp = fopen(filename,"a");
	for (int i = 0; i < statics_feature.size(); i++)
	{
		statics_feature[i].vectorize(fp);
	}
	in_addr addr;
	fclose(fp);
	//vector< vector<_tcp_srcport_build>> srcport_sequences;
	//for (map < unsigned int, vector< _packet_chunk_> > ::iterator it = prst->begin(); it != prst->end(); it++)
	//{
	//	if (it->first != inet_addr(ip))
	//	{
	//		continue;
	//	}
	//	vector<_tcp_srcport_build> tcp_srcport_data = pkt.get_tcp_srcport_data(prst, it->first);
	//	auto srcport_sequences_ = pkt.construct_tcpsrcport_sequences(tcp_srcport_data);

	//	if (srcport_sequences_.size())
	//	{
	//		srcport_sequences = srcport_sequences_;
	//		addr.S_un.S_addr = it->first;
	//		printf("%s : srcport size:%d \n", inet_ntoa(addr), srcport_sequences.size());
	//	}
	//}
	system("pause");
}
#endif