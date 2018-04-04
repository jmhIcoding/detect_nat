#pragma once
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "BaseTool.h"
#ifdef _WIN32
#include <windows.h>
#include <inaddr.h>
#endif
#ifdef __linux__
//添加linux下的socket相关的头文件
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#endif
#ifdef _WIN32

#endif
#include "define.h"
#include <time.h>
struct __counter__
{
	int count;
	int total;
	__counter__():
	count(0),total(0)
	{
		;
	}
};

class NetTool
{
public:
	void init()
	{
		if (init_flag == 0)
		{
#ifdef _WIN32
			WORD socketVersion = MAKEWORD(2, 2);
			WSADATA wsaData;
			if (WSAStartup(socketVersion, &wsaData) != 0)
			{
				printf("Error\n");
			}

			memset(buffer, 0, sizeof(buffer));
			this->server_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (server_fd == INVALID_SOCKET)
			{
				printf("socket error.\n");
			}
			sockaddr_in server_addr;
			server_addr.sin_family = AF_INET;
			server_addr.sin_port = htons(CPORT);
			server_addr.sin_addr.S_un.S_addr = INADDR_ANY;
			if (bind(this->server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) != 0)
			{
				printf("Bind Error\n");
			}
			this->PHOST_FD =-1;
#endif
#ifdef __linux__
		memset(buffer,0,sizeof(buffer));
		this->server_fd=socket(AF_INET,SOCK_DGRAM,0);
		if(this->server_fd==-1)
		{
				printf("socket error.\n");
				exit(-1);
				
		}
		sockaddr_in server_addr;
		server_addr.sin_family=AF_INET;
		server_addr.sin_port=htons(CPORT);
		server_addr.sin_addr.s_addr=inet_addr(CHOST);
		if(bind(this->server_fd,(sockaddr*)&server_addr,sizeof(server_addr))!= 0)
		{
				printf("Bind Error\n");
				exit(-1);
		}
		this->PHOST_FD=-1;
#endif
			init_flag = 1;
			ip2vector = new map<unsigned int ,vector < _packet_chunk_ > >();
		}
	}
	NetTool();
	NetTool(int srcport)
	{
#ifdef _WIN32

		
#endif
#ifdef __linux__
		
#endif
	}
	int send(char *dstip, int dstport, char *data, int length);
	~NetTool();
#ifdef _WIN32
	static void _recv_thread(void * _THIS)
	{
		NetTool * _this = (NetTool*)(_THIS);
		unsigned long threadid = 0;
		void * pthread = CreateThread(NULL, 0, _this->recv, _THIS, 0, &threadid);
		if (pthread == NULL)
		{
			printf("Create Thread Error\n");
			return;
		}
		else
		{
			_this->pthread = pthread;
		}
	}

	static DWORD __stdcall recv(void * _THIS)
	{
		NetTool* _this = (NetTool*)(_THIS);

		sockaddr_in remote_addr;
		int nAddrlen = sizeof(remote_addr);
		int t = 1;
		while (1)
		{
			memset(_this->buffer, 0, sizeof(_this->buffer));
			int ret = ::recv(_this->server_fd, _this->buffer, 4096, 0);
			if (ret > 0)
			{
				//printf("Get Message from Predict Model.\n");
				//接受参数,然后进入后续的操作
				//printf("%s \n", _this->buffer);
			}
			else
			{
				printf("Get Last Error %d \n", GetLastError());
			}
		}
		return 0;
	}
#endif
#ifdef __linux__
static void _recv_thread(void * _THIS)
{
		NetTool * _this =(NetTool*)(_THIS);
		pthread_t threadid=0;
		if(pthread_create(&threadid,NULL,recv,_THIS)!=0)
		{
				printf("create Thread Error\n");
				exit(-1);
		}
		else
		{
				_this->pthread=threadid;
		}
}

static void * recv(void * _THIS)
{
		NetTool* _this = (NetTool*)(_THIS);

		sockaddr_in remote_addr;
		int nAddrlen = sizeof(remote_addr);
		int t = 1;
		while (1)
		{
			memset(_this->buffer, 0, BUFSIZE);
			int ret = ::recv(_this->server_fd, _this->buffer, 4096, 0);
			if (ret > 0)
			{
				//printf("Get Message from Predict Model.\n");
				//接受参数,然后进入后续的操作
				printf("%s \n", _this->buffer);
				char *p = _this->buffer;
				char *ip_start;
				char *ip_end;
				char *label_start;
				ip_start =p;
				ip_end =p;
				int ip=0;
				label_start =p;
				int label=0;
				while((p-_this->buffer)<ret)
				{
					//printf("finding....\n");
					if((*p)==' ')
					{
						//*p='\0';//cut this string , for the seak of calling function of inet_addr()
						ip_end=p;
						label_start=p+1;
						//printf("get ip");
					}
					else if(*p==';')
					{
						char ipbuf[32]={0};
						memcpy(ipbuf,ip_start,ip_end-ip_start);
						//printf("%s\n",ipbuf);
						ip =inet_addr(ipbuf);
						//printf("%X\n",ip);
						//printf("%c\n",*((char*)label_start));
						label =*((char*)label_start)=='2'? 1:0;
						//printf("%d\n",label);
						if(_this->ip2NatCounter.find(ip)==_this->ip2NatCounter.end())
						{
							__counter__ tmpcnt;
							_this->ip2NatCounter[ip]=tmpcnt;
						}
						_this->ip2NatCounter[ip].total++;
						if(label==1)
						{
							_this->ip2NatCounter[ip].count++;
						}
						//printf("%s label:%d\n",ipbuf,label);
						ip_start = p+1;
					}
					p++;
				}
				//printf("End.\n");
			}
			else
			{
				printf("receivce error\n");
			}
		}
		return 0;
}
#endif
	map<unsigned int ,vector <_packet_chunk_> > *ip2vector;//ip映射到vector <_packet_chunk>上
	//map[inet_addr("192.168.0.1")]数据哇，要注意不同块之间的时间要映射回来
	map<unsigned int , __counter__ > ip2NatCounter;//ip映射到这个ip是nat的次数
	map<unsigned int ,int > ip2sockfd;//ip映射到socket fd
	
private:
#ifdef _WIN32
	SOCKET server_fd;
	SOCKET PHOST_FD;
	void * pthread=NULL;
#endif
#ifdef __linux__
	int server_fd;
	int PHOST_FD;
	pthread_t pthread=0;
#endif
	static int init_flag;
	char buffer[BUFSIZE];

};



