#pragma once
#include <WinSock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <mutex>
#include "define.h"
#include "IPCBase.h"
#include "BaseTool.h"

class Controller
	//一个socket 服务端作为控制器
{
public:

	Controller(char * pcap_file_name, char * filter,char * host = "127.0.0.1", int port = 10001) :
		socketTool(pcap_file_name,filter)
	{

		this->host = host;
		this->port = port;
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);
		//创建socket
		this->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);//建立TCP套接字
		
		sockaddr_in sin;
		sin.sin_family = AF_INET;
		sin.sin_port = htons(port);
		sin.sin_addr.S_un.S_addr = inet_addr(host);
		if (::bind(this->sock,(const sockaddr*) &sin, sizeof(sin)) == SOCKET_ERROR)
		{
			printf("Bind Error\n");
			system("pause");
			exit(-1);
		}
		listen(this->sock, 10);
		run();
	}
	void run()
	{
		SOCKET client;
		sockaddr_in remoteAddr;
		char buf[BufferSize] = { 0 };
		int nAddrlen = sizeof(remoteAddr); 
		client = accept(this->sock,(sockaddr*)&remoteAddr, &nAddrlen);
		printf("client connect.\n");
		while (true)
		{
			int ret = recv(client, buf, BufferSize, 0);
			if (ret>0)
			{
				display(buf, ret);
				int flag = ((int*)buf)[0];
				switch (flag)
				{
				case 0x00:
				{

							 break;//根据需要,准备数据包
				}
				case 0x01:
				{
							 handle_01(client);
							 break;//查询当前已经准备有多少可用的数据包
				}
				case 0x02:
				{
							 handle_02(buf,client);
							 break;
				} 
				default:
					break;
				}
			}

		}
	}
	void handle_02(char * buf,SOCKET sock)
	{
		int batch_size = ((int *)buf)[1];
		int pkt_num = ((int*)buf)[2];
		int pkt_length = ((int*)buf)[3];
		socketTool.send(sock, batch_size, pkt_num, pkt_length);
	}
	void handle_00(char * buf,SOCKET sock)
	{
		int batch_size = ((int *)buf)[1];
		int pkt_num = ((int*)buf)[2];
		int pkt_length = ((int*)buf)[3];
		if (this->_pkt_length == 0)
		{
			_pkt_length = pkt_length;
		}
		if (this->_available_pkt == 0)
		{
			this->_available_pkt = pkt_num;
		}
		if (this->_available_batch < batch_size)
			//插入数据
		{

		}
	}
	void handle_01(SOCKET sock)
		//处理数据包状态信息
	{
		int data[3] = { 0 };
		data[0] = this->_available_batch;
		data[1] = this->_available_pkt;
		data[2] = this->_pkt_length;
		send(sock,(char*)data,BufferSize,0);
	}
	void display(char * buf, int length)
	{
		for (int i = 1; i <= length; i++)
		{
			int ch = 0;
			ch=(unsigned char)buf[i-1];
			printf("0x%.2X ", ch);
			if (i % 8 == 0)
			{
				printf(" ");
			}
			if (i % 16 == 0)
			{
				printf("\n");
			}
		}
	}

	~Controller()
	{
		closesocket(sock);
		WSACleanup();
	}
private:
	char * host;
	unsigned short port; 
	SOCKET sock;
	int _pkt_length=0;//每个数据包的长度
	int _available_pkt=0;//目前可用的数据包个数
	int _available_batch=0;//目前准备好的数据批树
	BaseTool pktTool;
	IPC_Socket socketTool;
};

