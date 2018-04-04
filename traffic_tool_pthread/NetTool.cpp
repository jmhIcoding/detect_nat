#include "NetTool.h"


NetTool::NetTool()
{
	init();
	memset(buffer, 0, sizeof(buffer));
}


NetTool::~NetTool()
{
#ifdef _WIN32
	if (this->pthread != NULL)
	{
		printf("waiting for all sub thread to end.\n");
		WaitForSingleObject(this->pthread, INFINITE);  // 等待线程结束
	}
	WSACleanup();
#endif
#ifdef __linux__
	if(this->pthread!=0)
	{
			printf("waiting for all sub threads to end.\n");
			pthread_join(this->pthread,NULL);
			
	}
	if(this->PHOST_FD!=-1)
	{
		close(PHOST_FD);
	}
#endif
	delete ip2vector;
	
}

int NetTool::send(char *dstip, int dstport, char *data, int length)
{

	int client_fd;
	int sendsize=0;
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(dstport);
	
#ifdef _WIN32
	server_addr.sin_addr.S_un.S_addr = inet_addr(dstip);
	SOCKET sock ;
	if(PHOST_FD==-1)
	{
		sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		PHOST_FD=sock;
	}
	else
	{
		SOCKET sock =PHOST_FD;
	}
	sendsize= sendto(sock, data, length, 0, (sockaddr*)&server_addr, sizeof(server_addr));
#endif
#ifdef __linux__
	int sock_fd;
	server_addr.sin_addr.s_addr=inet_addr(dstip);
	if(PHOST_FD==-1)
	{
		PHOST_FD =sock_fd=socket(AF_INET,SOCK_DGRAM,0);
		
	}
	else
	{
		sock_fd = PHOST_FD;
	}
	sendsize= sendto(sock_fd,data,length,0,(sockaddr*)&server_addr, sizeof(server_addr));
	//close(sock_fd);
#endif
	if(sendsize==-1)
	{
		printf("Send Error. Error is %s .\n",strerror(errno));
	}
	return sendsize;
}
int NetTool::init_flag = 0;
