#include "NetTool.h"
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
#if 1
int main()
{
	NetTool udpTool;
	/*
	char *data = "172.16.30.34 2 4919 3418932 4111 700238 6200 8374 241 109 358 119 1101 125 291.000000 50.000000 0.404729 0.900664 0 2 9874.510834;"
		"172.16.30.154 1 16 4052 9 4518 0 15 10 0 1 0 0 3 623.000000 1.000000 0.987322 0.200000 0 1 0.003910;";
	udpTool.send(PHOST, PPORT, data, strlen(data));
	udpTool._recv_thread(&udpTool);
	udpTool.send(PHOST, PPORT, data, strlen(data));
	udpTool.send(PHOST, PPORT, data, strlen(data));
	*/
	char * interfaces="p4p1";
	char * filter="ip";
	char device_type = 0x00; //host
	int timegap=720;
	int big_timegap=3600;
	BaseTool pkt(interfaces,filter);
	char buf[512]={0};
	long start_block_timestamp=0;//每一块的开始时间戳哇
	long timeAccumulate=0;
	udpTool._recv_thread(&udpTool);
	while(1)
	{
		map<unsigned int ,vector < _packet_chunk_ > > * prst =pkt.cluster_raw_pakcets_online(0,timegap);
		start_block_timestamp =pkt.start_timestamp;

		for(map< unsigned int ,vector< _packet_chunk_> > ::iterator it = prst->begin();it!= prst->end();it++)
		{
			unsigned int ip =it->first;
			
			vector<_packet_statics_feature> statics_feature  = pkt.abstract_statics_feature(prst, ip, timegap, device_type);
			for(int i =0; i< statics_feature.size();i++)
			{
				//printf("Send New Data\n");
				memset(buf,0,512);
				statics_feature[i]._vectorize(buf,512,1);
				int sendSize=udpTool.send(PHOST,PPORT,buf,strlen(buf));
				//printf("Send %d bytes Well.\n",sendSize);
			}
			for(int j =0;j<(it->second).size();j++)
			{
				_packet_chunk_ tmp_chunk =(it->second)[j];
				tmp_chunk.timestamp+=start_block_timestamp;
				(*(udpTool.ip2vector))[ip].push_back(tmp_chunk);
			}
		}
		timeAccumulate+=timegap;
		delete prst;
		if((timeAccumulate % big_timegap)==0)
			//判断规模
		{
			printf("Caculate Nat Size.\n");
			for(map< unsigned int ,vector< _packet_chunk_ > > :: iterator it = udpTool.ip2vector->begin();it != udpTool.ip2vector->end();it++)
			{
				in_addr addr;
#ifdef _WIN32
				addr.S_un.S_addr = it->first;
#endif
#ifdef __linux__
				addr.s_addr=it->first;
#endif
				float rate =udpTool.ip2NatCounter[it->first].count*1.0/(udpTool.ip2NatCounter[it->first].total+0.00001);
				printf("%s nat rate : %f \n",inet_ntoa(addr),rate);
				if(rate>0.500)
				{
					vector<_tcp_srcport_build> tcp_srcport_data =pkt.get_tcp_srcport_data(udpTool.ip2vector,it->first);
					vector< vector <_tcp_srcport_build> > srcport_sequences;
					srcport_sequences =pkt.construct_tcpsrcport_sequences(tcp_srcport_data);
					if(srcport_sequences.size())
					{

						
						printf("############################Nat Found####################################\n");
						printf("%s : srcport size:%d \n", inet_ntoa(addr), srcport_sequences.size());
						printf("############################Nat Finish###################################\n");
					}
				}
			}
			while(!udpTool.ip2NatCounter.empty())
			{
				udpTool.ip2NatCounter.clear();
			}
			while(!udpTool.ip2vector->empty())
			{
				udpTool.ip2vector->clear();
			}
		}
	}
	
	
}
#endif
