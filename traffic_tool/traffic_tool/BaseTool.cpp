#include "BaseTool.h"


BaseTool::BaseTool()
{
}


BaseTool::~BaseTool()
{

}
void BaseTool::display(unsigned char * pkt_data, int len,int nextline)
{
	for (int i = 0; i < len;)
	{
		printf("%.2X ", pkt_data[i]);
		i += 1;
		if (i % nextline == 0)
		{
			printf("\n");
		}
	}
	printf("\n");
}

BaseTool::BaseTool(const char *pcapfilename)
{
	this->pcapt=pcap_open_offline(pcapfilename, this->errBuf);
	if (this->pcapt == NULL)
	{
		printf("Error when open pcap file.\n");
		system("pause");
		exit(-1);
	}
}
void BaseTool::setFilter(char *FilterString, pcap_t * pt)
//设置过滤器
{
	if (pt == NULL)
	{
		pt = this->pcapt;
	}
	bpf_program *fprog=new bpf_program();
	
	if (pcap_compile(pt, fprog, FilterString, 1, 0) == -1)
	{
		printf("compile filter error.\n");
	}

	if (pcap_setfilter(pt, fprog) == -1)
	{
		printf("set filter error.\n");
	}
}
vector< _packet> BaseTool::getPackets(pcap_t * pt )
//获取全部报文,主要用于通过文件获取报文
{
	if (pt == NULL)
	{
		pt = this->pcapt;
	}
	vector< _packet> rst;
	while (true)
	{
		vector< _packet> pkt = getNextPacket(pt);
		if (pkt.size())
		{
			rst.push_back(pkt[0]);
		}
		else
		{
			break;
		}
	}
	return rst;
}
vector< _packet> BaseTool::getNextPacket(pcap_t * pt )
//一个一个的获取报文
{
	vector< _packet> rst;
	if (pt == NULL)
	{
		pt = this->pcapt;
	}
	pcap_pkthdr pktheader;
	const u_char *pktdata = pcap_next(pt, &pktheader);
	if (pktdata != NULL)
	{
		if (this->start_timestamp == -1)
		{
			this->start_timestamp = pktheader.ts.tv_sec;
		}
		_packet packet;
		packet.len = pktheader.caplen;
		packet.timestamp = abs(pktheader.ts.tv_sec-this->start_timestamp);
		packet.data = (unsigned char *)malloc(sizeof(unsigned char)*packet.len);
		memcpy(packet.data, pktdata, packet.len);
		rst.push_back(packet);
	}
	return rst;
}
int BaseTool::getpayload_offset(unsigned char* pkt_data)
//TCP/UDP协议：返回正确的偏移
//非TCP/UDP协议：返回0
{
	ip_header *ih;
	udp_header *udp;
	tcp_header *tcp;
	u_int ip_len;
	ih = (ip_header*)(pkt_data + 14);//把以太网头偏移
	int ip_flag = (*(u_short*)(pkt_data + 12));
	if (ip_flag!=0x0008)//非ip协议
	{
		return 0;
	}
	int protocol_type = *(pkt_data + 14 + 9);
	int tcp_udp_header_length = 0;
	if (protocol_type == 6)
		//tcp
	{
		tcp = (tcp_header*)(pkt_data + 14 + 20);
		tcp_udp_header_length = 4*(((tcp->tcpHeader_reserve) & 0xF0) >> 4);
	}
	else if (protocol_type == 17)
		//udp
	{
		udp = (udp_header*)(pkt_data + 14 + 20);
		tcp_udp_header_length = 8;
	}
	else
		//非ip协议
	{
		return 0;
	}
	return  14 + 20 + tcp_udp_header_length;
}
vector<_packet_host_cont>  BaseTool::get_host_count_data(pcap_t * pt, int ipaddr)
//从报文中获取给定IP的ipid,tcp seq,源端口号.结果保存在一个vector里面
{
	vector<_packet_host_cont> rst;
	if (pt == NULL)
	{
		pt = this->pcapt;
	}
	while (true)
	{
		vector<_packet> pkt = this->getNextPacket(pt);
		if (pkt.size())
		{
			_packet_host_cont count_info;

			count_info.timestamp = pkt[0].timestamp;
			int ip_flag = (*(u_short*)(pkt[0].data + 12));
			if (ip_flag != 0x0008)//非ip协议
			{
				continue;
			}
			ip_header *ih;
			udp_header *udp;
			tcp_header *tcp;
			u_int ip_len;
			ih = (ip_header*)(pkt[0].data + 14);//把以太网头偏移
			if (ih->saddr != ipaddr)
			{
				continue;
			}
			//count_info.ipid = ih->identification;//ip ID的赋值
			little_endian2big_endian((u_char*)&(ih->identification), 2, (u_char*)&(count_info.ipid));

			if (ih->proto == 6)
				//tcp协议,提取tcp sequence
			{
				tcp = (tcp_header*)(pkt[0].data + 14 + 20);
				//count_info.tcpseq = tcp->sequence;
				little_endian2big_endian((u_char*)&(tcp->sequence), 4, (u_char*)&(count_info.tcpseq));
				//count_info.srcport = tcp->sport;
				little_endian2big_endian((u_char*)&(tcp->sport), 2, (u_char*)&(count_info.srcport));
			}
			//else if (ih->proto==17)
				//udp协议
			//{
			//	udp = (udp_header*)(pkt[0].data + 14 + 20);
				//count_info.srcport = udp->sport;
			//	little_endian2big_endian((u_char*)&(udp->sport), 2, (u_char*)&(count_info.srcport));
			//}
			rst.push_back(count_info);
		}
		else
		{
			break;
		}

	}
	return rst;
}
vector< vector<_ipid_build> > BaseTool::construct_ipid_sequence(vector<_packet_host_cont>& _host_count)
/*
根据_host_count里面记录的ipid序列,重构ipid_sequence,将ipid数据分成若干个不同的序列。
方法参照论文: counting nated hosts by observing tcp ip field behaviors.
返回 D
D[i]=[d1,d2,d3,d4...,dn]
条件:
0<=d[m](t)-d[m-1](t)<= timelimit ,也就是相邻的di,dj他们之间时间差值不得超过timelimit
d[m]-d[m-1]<=gaplimit,也就是相邻的di,dj差值不得超过gaplimit.
如果不满足上述重要条件,则当ipid附加到一个ipid_sequence后面去。
按照论文:timelimt=5(秒),gaplimt=64
*/
{	
	long timelimit = 300;
	u_short gaplimit = 64;
	long MemberCri = 5;
	long MemberCri2 = 50;

	vector< vector<_ipid_build> >ipid_sequences;
	while (!ipid_sequences.empty())
	{
		ipid_sequences.pop_back();
	}
	for (int i = 0; i < _host_count.size(); i++)
	{
		u_short ipid = _host_count[i].ipid;
		long timestamp = _host_count[i].timestamp;
		bool flag = 0;
		for (int j = 0; j < ipid_sequences.size(); j++)
		{
			auto ipid_diff = (ipid - ipid_sequences[j][ipid_sequences[j].size() - 1].ipid)%32768;
			while (ipid_diff<0)
			{
				ipid_diff += 32768;
			}
			auto timestamp_diff = timestamp - ipid_sequences[j][ipid_sequences[j].size() - 1].timestamp;
			if ((ipid_diff < gaplimit) && (ipid_diff >= 0) && (timestamp_diff < timelimit) && (timestamp_diff >= 0))
			{
				ipid_sequences[j].push_back({ ipid, timestamp });
				flag = 1;
				continue;
			}
			else
			{
				continue;
			}
		}
		if (flag == 0)
		{
			vector<_ipid_build> *ipid_sequence =new vector< _ipid_build>;
			(*ipid_sequence).push_back({ ipid, timestamp });
			ipid_sequences.push_back(*ipid_sequence);
		}
	}
	vector< vector<_ipid_build> > rst;
	for (int i = 0; i < ipid_sequences.size(); i++)
		//过滤太短的
	{
		if (ipid_sequences[i].size() >= MemberCri)
		{
			rst.push_back(ipid_sequences[i]);
		}
	}
	//过滤与其它组重叠的,进行合并,短的合并到长的里面去
	vector < vector<_ipid_build> > rst2;
	rst2.push_back(rst[0]);
	for (int i = 1; i < rst.size(); i++)
	{
		bool flag = 0;
		for (int j = 0; j < rst2.size(); j++)
		{
			float l1 = rst[i][0].ipid;
			float r1 = rst[i][rst[i].size() - 1].ipid;
			float l2 = rst2[j][0].ipid;
			float r2 = rst2[j][rst2[j].size() - 1].ipid;
			float overlapping1 = max(line_overlap(l1, r1, l2, r2), line_overlap(l2, r2, l1, r1));
			l1 = rst[i][0].timestamp;
			r1 = rst[i][rst[i].size() - 1].timestamp;
			l2 = rst2[j][0].timestamp;
			r2 = rst2[j][rst2[j].size() - 1].timestamp;
			float overlapping2 = max(line_overlap(l1, r1, l2, r2), line_overlap(l2, r2, l1, r1));
			if (overlapping1 >= gaplimit*0.8 && overlapping2 >= timelimit*0.8)
				//合并
			{
				vector< _ipid_build> ipid_sequence;
				int ii = 0, jj = 0;
				while (true)
				{
					if (rst[i][ii].ipid <= rst2[j][jj].ipid)
					{
						if (ipid_sequence.empty()||rst[i][ii].ipid != ipid_sequence[ipid_sequence.size() - 1].ipid)
						{
							ipid_sequence.push_back(rst[i][ii]);
						}
						ii++;
					}
					else
					{
						if (ipid_sequence.empty() || rst2[j][jj].ipid != ipid_sequence[ipid_sequence.size() - 1].ipid)
						{
							ipid_sequence.push_back(rst2[j][jj]);
						}
						jj++;
					}
					if (ii >= rst[i].size())
					{
						break;
					}
					if (jj >= rst2[j].size())
					{
						break;
					}
				}
				while (ipid_sequence.empty() || ii < rst[i].size())
				{
					if (rst[i][ii].ipid != ipid_sequence[ipid_sequence.size() - 1].ipid)
					{
						ipid_sequence.push_back(rst[i][ii]);
					}
					ii++;
				}
				while (ipid_sequence.empty() || jj < rst2[j].size())
				{
					if (rst2[j][jj].ipid != ipid_sequence[ipid_sequence.size() - 1].ipid)
					{
						ipid_sequence.push_back(rst2[j][jj]);
					}
					jj++;
				}
				rst2[j] = ipid_sequence;
				flag = 1;
				break;
			}

		}
		if (flag==0)
			 {
				 rst2.push_back(rst[i]);
			 }
	}
	//合并之后,再把那些太短的删除掉
	while (true)
	{

		bool flag = 0;
		for (vector< vector<_ipid_build> >::iterator p = rst2.begin(); p != rst2.end(); p++)
		{
			if (p->size() < MemberCri2)
			{
				rst2.erase(p);
				flag = 1;
				break;
			}
		}
		if (flag == 0)
		{
			break;
		}
	}
	//再把那些out_of_order占比太多的去掉
	while (true)
	{
		bool flag = 0;
		for (vector< vector<_ipid_build> >::iterator p = rst2.begin(); p != rst2.end(); p++)
		{
			int out_of_order_count = 0;
			for (int j = 0; j < p->size() - 1; j++)
			{
				auto diff = ((*p)[j + 1].ipid - (*p)[j].ipid);
				if (diff != 0 && diff != 1)
				{
					out_of_order_count++;
				}
			}
			if (out_of_order_count>p->size()*0.5)
			{
				rst2.erase(p);
				flag = 1;
			}
		}
		if (flag == 0)
		{
			break;
		}
	}
	return rst2;
}