#pragma once
#include <windows.h>
#include "define.h"
#include <time.h>
#include "BaseTool.h"
using namespace std;
class IPC_MemoryMap
{
public:
	IPC_MemoryMap(char *mapFile_name=MAPFILENAME)
	{
		void * pfile = CreateFile(LPCSTR(mapFile_name),GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		void * fmaping = CreateFileMapping(pfile, NULL, PAGE_READWRITE, 0, max_map_size, LPCSTR(tag_name));
		printf("%d\n", GetLastError()); 
		map_file_point = MapViewOfFile(fmaping,FILE_MAP_WRITE, 0, 0, max_map_size);
		if (map_file_point == NULL)
		{
			printf("OS Error With Code %d\n", GetLastError());
			system("pause");
			exit(-1);
		}
	}
	~IPC_MemoryMap()
	{
		if (map_file_point)
		{
			UnmapViewOfFile(map_file_point);
		}
	}
	char & operator[](int index)
	{
		if (index < max_map_size)
		{
			return ((char*)map_file_point)[index];
		}
		else
		{
			printf("Internal Error. map_file_point out of range.\n");
			system("pause");
			exit(-1);
		}
	}
private:
	void * map_file_point;
};
class IPC_Socket
{
public:
	IPC_Socket(char *pcap_file_name,char *filter):
		pktTool(pcap_file_name)
	{
		pktTool.setFilter(filter);
	}
	~IPC_Socket()
	{

	}
	void send(SOCKET sock, int batch_size, int pkt_num, int pkt_length)
	{
		char * buf = (char*)malloc(sizeof(char)*batch_size*pkt_length*pkt_num);
		gain_data(batch_size, pkt_num, pkt_length, buf);
		::send(sock, buf, batch_size*pkt_num*pkt_length, 0);
		free((void*)buf);
	}
private:
	void gain_data(int batch_size, int pkt_num, int pkt_length,char * dstBuf)
	{
		int offset_of_buf=0;
		int packet_index = 0;
		for (int i = 0; i < batch_size; i++)
		{
			for (int j = 0; j < pkt_num; j++)
			{
				vector<_packet> pkt = pktTool.getNextPacket();
				if (!pkt.size())
				{
					pkt.push_back( packets[packet_index]);
					packet_index %= packets.size();
				}
				else
				{
					packets.push_back(pkt[0]);
				}
				int offset = pktTool.getpayload_offset(pkt[0].data);
				if (offset <= 16)
					//非TCP/UDP载荷或者长度不够
				{
					continue;
				}
				for (int k=0; k< max(pkt[0].len, pkt_length); k++)
				{
					if (k >= pkt_length)
					{
						break;
					}
					if ((k+offset)>=pkt[0].len)
						//用0补齐
					{
						dstBuf[offset_of_buf++] = 0x00;
					}
					else
					{
						dstBuf[offset_of_buf++] = pkt[0].data[k+offset];
					}

				}
			}
		}
		for (; offset_of_buf < batch_size*pkt_num*pkt_length; offset_of_buf++)
			//后面不足的用0补齐
		{
			dstBuf[offset_of_buf] = 0x00;
		}
	}
private:
	BaseTool pktTool;
	vector<_packet> packets;
};
