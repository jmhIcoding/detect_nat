#include "NetTool.h"


NetTool::NetTool()
{
	init();
	memset(buffer, 0, sizeof(buffer));
}


NetTool::~NetTool()
{
#ifdef _WIN32
	WSACleanup();
#endif
}

int NetTool::send(char *dstip, int dstport, char *data, int length)
{
	int client_fd;
	int sendsize=0;
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(dstport);
	server_addr.sin_addr.S_un.S_addr = inet_addr(dstip);
#ifdef _WIN32
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	sendsize= sendto(sock, data, length, 0, (sockaddr*)&server_addr, sizeof(server_addr));
#endif
#ifdef __linux__
#endif
	return sendsize;
}
int NetTool::init_flag = 0;
