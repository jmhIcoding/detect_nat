#include <stdio.h>
#include <stdlib.h>
#include "BaseTool.h"
#include "IPCBase.h"
#include "EntroyEstimation.h"
#include "Controller.h"
int _main()
{
	Controller cont("E:\\TempWorkStation\\GraduatePaper\\Captures\\hyxd.pcap", "dst host 42.186.22.100");

	return 0;
}
int __main()
{
	//Controller cont("127.0.0.1",10001);

	//IPC_MemoryMap ipc = IPC_MemoryMap();
	//int i = 0;
	//while (true)
	//{
	//	ipc[0] = rand()%256;
	//	unsigned char c = (unsigned char)ipc[0];
	//	printf("%d  :%d \n", i++,c);
	//	Sleep(1000);
	//}
	//system("pause");
	BaseTool pktTool("E:\\TempWorkStation\\GraduatePaper\\Captures\\hyxd.pcap");
	char * sample_entropy_save_file = "sample_entropy.data";
	char * benchmark_entropy_save_file = "benchmark_entropy.data";
	FILE *fp_sam = fopen(sample_entropy_save_file,"w");
	FILE *fp_ben = fopen(benchmark_entropy_save_file, "w");
	//pktTool.setFilter("src host 52.231.74.74");//绝地求生
	//pktTool.setFilter("host 202.89.233.101");//bing
	//pktTool.setFilter("src host 182.254.110.86");//LOL
	//pktTool.setFilter("host 121.195.186.227");//xzsq
	//pktTool.setFilter("dst host 182.254.33.149");//oicq
	pktTool.setFilter("dst host 42.186.22.100");//荒野行动
	//pktTool.setFilter("src host 223.252.244.201");//暗黑破坏神
	//pktTool.setFilter("host 182.150.35.234");
	//pktTool.setFilter("dst host 106.2.55.218"); //梦幻西游
	//pktTool.setFilter("dst host 223.252.254.225");//守望先峰
	//pktTool.setFilter("src host 182.254.110.91");//DNF
	vector< _packet> pkt = pktTool.getPackets();
	//int index = 241;
	//index--;
	//int offset = pktTool.getpayload_offset(pkt[index].data);
	//pktTool.display(pkt[index].data, pkt[index].len);
	//pktTool.display(pkt[index].data +offset, pkt[index].len - offset);
	int cnt = 2048;
	int encrypted = 0;
	int total = 0;
	fprintf(fp_sam, "[");
	fprintf(fp_ben, "[");
	char buf[1024] = { 0 };
	for (int i = 0; i <pkt.size(); i++)
	{
		memset(buf, 0, 1024);
		int offset=pktTool.getpayload_offset(pkt[i].data);
		//printf("%d--> %f\n",i+1, HMLE(pkt[i].data+offset, pkt[i].len-offset));
		int flag = is_Encrypted(pkt[i].data+offset, pkt[i].len - offset);
		if (flag == 0)
		{
			if (total < cnt)
			{
				printf("%0.5d,%0.6f,%0.6f,%d,Encrypted?:", i + 1, HMLE(pkt[i].data + offset, pkt[i].len - offset), hu(pkt[i].len - offset), pkt[i].len - offset);
				printf("No \n");
			}
			total++;
			fprintf(fp_sam, "%0.6f,", HMLE(pkt[i].data + offset, pkt[i].len - offset));
			fprintf(fp_ben, "%0.6f,", hu(pkt[i].len - offset));
		}
		else if (flag == 1)
		{
			if (total < cnt)
			{
				printf("%0.5d,%0.6f,%0.6f,%d,Encrypted?:", i + 1, HMLE(pkt[i].data + offset, pkt[i].len - offset), hu(pkt[i].len - offset), pkt[i].len - offset);
				printf("Yes\n");
			}
			encrypted++;
			total++;
			fprintf(fp_sam, "%0.6f,", HMLE(pkt[i].data + offset, pkt[i].len - offset));
			fprintf(fp_ben, "%0.6f,", hu(pkt[i].len - offset));
		}
		
	}
	fprintf(fp_sam, "0]");
	fprintf(fp_ben, "0]");
	fclose(fp_sam);
	fclose(fp_ben);
	printf("%f\n", encrypted*1.0 / total);
	system("pause");
	return 0;
}