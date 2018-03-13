#include <stdio.h>
#include <stdlib.h>
#include "BaseTool.h"
#include "IPCBase.h"
#include "EntroyEstimation.h"
#include "Controller.h"
#include <inaddr.h>
int main()
{
	BaseTool pkt("C:\\Users\\dell\\Documents\\detect_nat\\pcaps\\03_13_14_30_19_40_172_16_30_34_windows_7.pcap");
	
	auto rst =pkt.get_host_count_data(NULL, inet_addr("172.16.30.34"));
	for (int i = 0; i < rst.size(); i++)
	{
		//printf("%d:%X:%X  ", rst[i].ipid,rst[i].tcpseq,rst[i].timestamp);
		if (i<(rst.size()-1)&&(rst[i + 1].ipid - rst[i].ipid)>2)
		{
			printf("\n\n new ip id sequence   \n");
		}
	}
	vector< vector<_ipid_build> > ipid_sequences = pkt.construct_ipid_sequence(rst);
	printf("size: %d \n", ipid_sequences.size());
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