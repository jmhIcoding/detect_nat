#pragma once
#ifdef _WIN32
#include <windows.h>
#include <inaddr.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#endif
#ifdef __linux__
//添加linux下的socket相关的头文件
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#endif
#ifdef _WIN32
#endif
#include "define.h"
#include <time.h>

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
#endif
			init_flag = 1;
		}
	}
	NetTool();
	NetTool(int srcport)
	{
#ifdef _WIN32
		init();
		memset(buffer, 0, sizeof(buffer));
		this->server_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (server_fd == INVALID_SOCKET)
		{
			printf("socket error.\n");
		}
		sockaddr_in server_addr;
		server_addr.sin_family=AF_INET;
		server_addr.sin_port =htons(srcport);
		server_addr.sin_addr.S_un.S_addr = INADDR_ANY;
		if (bind(this->server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) != 0)
		{
			printf("Bind Error\n");
		
		}
		sockaddr_in remote_addr;
		int nAddrlen=sizeof(remote_addr);
		while (1)
		{

			int ret = recvfrom(this->server_fd, buffer, 4096, 0, (sockaddr *)& remote_addr, &nAddrlen);
			if (ret > 0)
			{
				printf("%s \n", buffer);
			}
		}
#endif
#ifdef __linux__
		
#endif
	}
	int send(char *dstip, int dstport, char *data, int length);
	~NetTool();
private:
#ifdef _WIN32
	SOCKET server_fd;
#endif
#ifdef __linux__
	int server_fd;
#endif
	static int init_flag;
	char buffer[BUFSIZE];
};



