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
BaseTool::BaseTool(const char *interfaces, char *filters)
//���߻�ȡ����,������Ҫʹ��filters�Ƚ��й���
{
	{
		pcap_if_t *alldevs;
		pcap_if_t *d;
		int inum;
		int i = 0;
		pcap_t *adhandle;
		char errbuf[PCAP_ERRBUF_SIZE];

		/* Retrieve the device list on the local machine */
		if (pcap_findalldevs(&alldevs,errBuf) == -1)
		{
			fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
			exit(1);
		}

		/* Print the list */
		for (d = alldevs; d; d = d->next)
		{
			printf("%d. %s\n", ++i, d->name);
			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}

		if (i == 0)
		{
			printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		}
	}
	this->pcapt = pcap_open_live(interfaces, 65535,1 , 1000, errBuf);
	if (this->pcapt == NULL)
	{
		printf("Error when open interface %s.\n", interfaces);
		system("pause");
		exit(-1);
	}
	setFilter(filters, this->pcapt);

}
void BaseTool::setFilter(char *FilterString, pcap_t * pt)
//���ù�����
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
//��ȡȫ������,��Ҫ����ͨ���ļ���ȡ����
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
//һ��һ���Ļ�ȡ����
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
//TCP/UDPЭ�飺������ȷ��ƫ��
//��TCP/UDPЭ�飺����0
{
	ip_header *ih;
	udp_header *udp;
	tcp_header *tcp;
	u_int ip_len;
	ih = (ip_header*)(pkt_data + 14);//����̫��ͷƫ��
	int ip_flag = (*(u_short*)(pkt_data + 12));
	if (ip_flag!=0x0008)//��ipЭ��
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
		//��ipЭ��
	{
		return 0;
	}
	return  14 + 20 + tcp_udp_header_length;
}
vector<_packet_host_cont>  BaseTool::get_host_count_data(pcap_t * pt, int ipaddr)
//�ӱ����л�ȡ����IP��ipid,tcp seq,Դ�˿ں�.���������һ��vector����
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
			if (ip_flag != 0x0008)//��ipЭ��
			{
				continue;
			}
			ip_header *ih;
			udp_header *udp;
			tcp_header *tcp;
			u_int ip_len;
			ih = (ip_header*)(pkt[0].data + 14);//����̫��ͷƫ��
			if (ih->saddr != ipaddr)
			{
				continue;
			}
			/*
			�ѹ㲥���Ĺ���
			*/
			if (ih->daddr == 0xffffffff || ih->saddr == 0xffffffff)
			{
				continue;
			}

			if (ih->daddr & 0xff000000 == 0xff000000 || ih->saddr & 0xff000000 == 0xff000000)
				//�ڲ��Ĺ㲥����
			{
				continue;
			}
			//count_info.ipid = ih->identification;//ip ID�ĸ�ֵ
			little_endian2big_endian((u_char*)&(ih->identification), 2, (u_char*)&(count_info.ipid));

			if (ih->proto == 6)
				//tcpЭ��,��ȡtcp sequence
			{
				tcp = (tcp_header*)(pkt[0].data + 14 + 20);
				//count_info.tcpseq = tcp->sequence;
				little_endian2big_endian((u_char*)&(tcp->sequence), 4, (u_char*)&(count_info.tcpseq));
				//count_info.srcport = tcp->sport;
				little_endian2big_endian((u_char*)&(tcp->sport), 2, (u_char*)&(count_info.srcport));
			}
			//else if (ih->proto==17)
				//udpЭ��
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
vector< vector<_ipid_build> > BaseTool::construct_ipid_sequence(vector<_packet_host_cont>& _host_count,int timelens)
/*
����_host_count�����¼��ipid����,�ع�ipid_sequence,��ipid���ݷֳ����ɸ���ͬ�����С�
������������: counting nated hosts by observing tcp ip field behaviors.
���� D
D[i]=[d1,d2,d3,d4...,dn]
����:
0<=d[m](t)-d[m-1](t)<= timelimit ,Ҳ�������ڵ�di,dj����֮��ʱ���ֵ���ó���timelimit
d[m]-d[m-1]<=gaplimit,Ҳ�������ڵ�di,dj��ֵ���ó���gaplimit.
���������������Ҫ����,��ipid���ӵ�һ��ipid_sequence����ȥ��
��������:timelimt=5(��),gaplimt=64
*/
{	
	long timelimit = 20;
	u_short gaplimit = 128;
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
		if (timelens>0 && timestamp > timelens)
		{
			break;
		}
		bool flag = 0;
		for (int j = 0; j < ipid_sequences.size(); j++)
		{
			auto ipid_diff = (ipid - ipid_sequences[j][ipid_sequences[j].size() - 1].ipid)%65536;
			while (ipid_diff<0)
			{
				ipid_diff += 65536;
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
		//����̫�̵�
	{
		if (ipid_sequences[i].size() >= MemberCri)
		{
			rst.push_back(ipid_sequences[i]);
		}
	}
	
	//�������������ص���,���кϲ�,�̵ĺϲ�����������ȥ
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
				//�ϲ�
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
		if (rst2.size() == 47)
		{
			printf("debug now\n");
		}
	}
	
	//�ϲ�֮��,�ٰ���Щ̫�̵�ɾ����
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
	//�ٰ���Щout_of_orderռ��̫���ȥ��
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
				break;
			}
		}
		if (flag == 0)
		{
			break;
		}
	}
	return rst2;
}
map<unsigned int, vector < _packet_chunk_> >* BaseTool::cluster_raw_pakcets(pcap_t *pt)
//��ԭʼ����,����Դip�����ռ�
//2018-03-22
{
	static unsigned int relative_id=0;
	map<unsigned int, vector< _packet_chunk_> >* prst = new map<unsigned int, vector< _packet_chunk_> >;
	while (!prst->empty())
		//���
	{
		prst->clear();
	}
	if (pt == NULL)
	{
		pt = this->pcapt;
	}
	while (true)
	{
		vector<_packet> pkt = this->getNextPacket(pt);
		relative_id = (relative_id + 1) % 4294967296;
		if (pkt.size())
		{
			_packet_chunk_ packet_info;

			packet_info.timestamp = pkt[0].timestamp;
			if (!(packet_info.timestamp > 0*60  && packet_info.timestamp<60*60 ))
			{
				continue;
			}
			int ip_flag = (*(u_short*)(pkt[0].data + 12));
			if (ip_flag != 0x0008)//��ipЭ��
			{
				continue;
			}
			ip_header *ih;
			udp_header *udp;
			tcp_header *tcp;
			u_int ip_len;
			ih = (ip_header*)(pkt[0].data + 14);//����̫��ͷƫ��
			/*
			�ѹ㲥���Ĺ���
			*/
			//if (ih->daddr == 0xffffffff || ih->saddr == 0xffffffff)
			//{
			//	continue;
			//}
	
			//if (ih->daddr&0xff000000==0xff000000||ih->saddr&0xff000000==0xff000000)
			//	//�ڲ��Ĺ㲥����
			//{
			//	continue;
			//}
			little_endian2big_endian((u_char*)&(ih->identification), 2, (u_char*)&(packet_info.ipid));
			packet_info.ttl = ih->ttl;
			packet_info.byte_length = pkt[0].len - 14;
			packet_info.relative_id = relative_id;
			if (ih->proto == 6)
				//tcpЭ��,��ȡtcp sequence
			{
				packet_info.utility_flag |= TCPFLAG;
				tcp = (tcp_header*)(pkt[0].data + 14 + 20);
				unsigned short srcport;
				unsigned short dstport;
				little_endian2big_endian((u_char*)&(tcp->sequence), 4, (u_char*)&(packet_info.tcp_sequecnce));
				
				little_endian2big_endian((u_char*)&(tcp->sport), 2, (u_char*)&(srcport));

				little_endian2big_endian((u_char*)&(tcp->dport), 2, (u_char*)&(dstport));
				packet_info.srcport = srcport;
				if (srcport == 80 || srcport == 443 || dstport == 80 || srcport == 443)
					//http ����
				{
					packet_info.utility_flag |= HTTPFLAG;
				}
				if (tcp->flag & 0x01)
					//fin ����
				{
					packet_info.utility_flag |= FINFLAG;
				}
				if (tcp->flag & 0x02)
					//SYN����
				{
					packet_info.utility_flag |= SYNFLAG;
				}
				if (tcp->flag & 0x04)
					//reset ����
				{
					packet_info.utility_flag |= RSTFLAG;
				}
			}
			else if (ih->proto==17)
			//udpЭ��
			{
				packet_info.utility_flag |= UDPFLAG;
				udp = (udp_header*)(pkt[0].data + 14 + 20);
				unsigned short srcport, dstport;
				little_endian2big_endian((u_char*)&(udp->sport), 2, (u_char*)&(srcport));
				little_endian2big_endian((u_char*)&(udp->dport), 2, (u_char*)&(dstport));
				if (srcport == 53 || dstport == 53)
				{
					packet_info.utility_flag |= DNSFLAG;
				}
				if (srcport == 8000 || dstport == 8000)
					
				{
					unsigned char * pdata = pkt[0].data + 14 + 20 + sizeof(udp_header);
					if (pdata[0] == 0x02)
						//oicqЭ��
					{
						little_endian2big_endian(pdata +6,sizeof(unsigned int), (unsigned char *)&packet_info.oicq_number)  ;
					}
				}
			}
			
			//���Ͼ��Ѿ��������
			packet_info.dstip = ih->daddr;
			//��src ip ��˵,������ǳ�ȥ�İ�
			packet_info.flag = 1;
			if (prst->find(ih->saddr) != prst->end())
				//�Ѿ��ҵ���,������ݲ���
			{
				(*prst)[ih->saddr].push_back(packet_info);
			}
			else
			{
				(*prst)[ih->saddr].push_back(packet_info);
			}
			//��dst ip��˵,������ǽ����İ�
			packet_info.dstip = ih->saddr;
			packet_info.flag = 0;
			(*prst)[ih->daddr].push_back(packet_info);
			//�ͷű���ռ�õ��ڴ�
			free(pkt[0].data);
		}
		else
		{
			break;
		}

	}
	return prst;
}
vector<_ipid_build> BaseTool::get_ipid_data(map<unsigned int, vector<_packet_chunk_>> * p_packets, unsigned int srcip)
//����Դip,��ȡ���е�ipidԭʼ���ݡ��������еĳ��ڱ���
{
	vector<_ipid_build> ipids;
	vector<_packet_chunk_>& packets = (*p_packets)[srcip];
	for (int i = 0; i < packets.size(); i++)
	{
		if (packets[i].flag == 1 && (packets[i].utility_flag&SYNFLAG) == SYNFLAG)
			//��ȥ�����ݰ�
		{
			_ipid_build ipid_info;
			ipid_info.ipid = packets[i].ipid;
			ipid_info.relative_id = packets[i].relative_id;
			ipid_info.timestamp = packets[i].timestamp;
			ipids.push_back(ipid_info);
		}
	}
	return ipids;
}
vector<_tcp_sequence_build> BaseTool::get_tcp_seq_data(map<unsigned int, vector<_packet_chunk_>> * p_packets, unsigned int srcip)
//����Դip,��ȡ���е�tcp_seqԭʼ���ݡ��������еĳ��ڱ���
{
	vector<_tcp_sequence_build> tcp_seqs;
	vector<_packet_chunk_> & packets = (*p_packets)[srcip];
	for (int i = 0; i < packets.size(); i++)
	{
		if (packets[i].flag == 1)
			//��ȥ�����ݰ�
		{
			if ((packets[i].utility_flag&TCPFLAG) == TCPFLAG && (packets[i].utility_flag&SYNFLAG)==SYNFLAG)
			{
				_tcp_sequence_build sequence;
				sequence.relative_id = packets[i].relative_id;
				sequence.tcp_sequence = packets[i].tcp_sequecnce;
				sequence.timestamp = packets[i].timestamp;
				tcp_seqs.push_back(sequence);
			}
		}
	}
	return tcp_seqs;
}
vector<_tcp_srcport_build> BaseTool:: get_tcp_srcport_data(map<unsigned int, vector<_packet_chunk_>> * p_packets, unsigned int srcip)
//����Դip,��ȡ���е�tcp_srcportԭʼ���ݡ��������е�tcp.syn==1���ڱ���
{
	vector<_tcp_srcport_build> tcp_srcports;
	vector<_packet_chunk_> & packets = (*p_packets)[srcip];
	for (int i = 0; i < packets.size(); i++)
	{
		if (packets[i].flag == 1)
		{
			if ((packets[i].utility_flag&TCPFLAG) == TCPFLAG && (packets[i].utility_flag&SYNFLAG) == SYNFLAG)
			{
				_tcp_srcport_build srcport;
				srcport.relative_id = packets[i].relative_id;
				srcport.srcport = packets[i].srcport;
				srcport.timestamp = packets[i].timestamp;
				//��һЩ����˿ڹ��˵�
				if (srcport.srcport <= 1024)
				{
					continue;
				}
				//if (packets[i].dstip == inet_addr("43.239.158.85"))
				//	//����ù�ɳ��������������ӵ�vps������
				//{
				//	continue;
				//}
				tcp_srcports.push_back(srcport);
			}
		}
	}
	return tcp_srcports;
}
vector < vector< _ipid_build > >BaseTool::construct_ipid_sequences(const vector<_ipid_build> & ipid_data)
//����ipid_buildԭʼ����,����ipid����
{
	long timelimit = 6;
	u_short gaplimit = 1024;
	long MemberCri = 10;
	long MemberCri2 = 100;

	vector< vector<_ipid_build> >ipid_sequences;
	while (!ipid_sequences.empty())
	{
		ipid_sequences.pop_back();
	}
	for (int i = 0; i < ipid_data.size(); i++)
	{
		u_short ipid = ipid_data[i].ipid;
		long timestamp = ipid_data[i].timestamp;
		unsigned int relative_id = ipid_data[i].relative_id;
		bool flag = 0;
		for (int j = 0; j < ipid_sequences.size(); j++)
		{
			auto ipid_diff = (ipid - ipid_sequences[j][ipid_sequences[j].size() - 1].ipid) % 65536;
			while (ipid_diff<0)
			{
				ipid_diff += 65536;
			}
			auto timestamp_diff = timestamp - ipid_sequences[j][ipid_sequences[j].size() - 1].timestamp;
			if ((ipid_diff < gaplimit) && (ipid_diff >= 0) && (timestamp_diff < timelimit) && (timestamp_diff >= 0))
			{
				ipid_sequences[j].push_back({ ipid, timestamp ,relative_id});
				flag = 1;
				break;
			}
		}
		if (flag == 0)
		{
			vector<_ipid_build> *ipid_sequence = new vector< _ipid_build>;
			(*ipid_sequence).push_back({ ipid, timestamp });
			ipid_sequences.push_back(*ipid_sequence);
		}
	}
	vector< vector<_ipid_build> > rst;
	for (int i = 0; i < ipid_sequences.size(); i++)
		//����̫�̵�
	{
		if (ipid_sequences[i].size() >= MemberCri)
		{
			rst.push_back(ipid_sequences[i]);
		}
	}

	//�������������ص���,���кϲ�,�̵ĺϲ�����������ȥ
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
			float overlapping1 = max( line_overlap(l1, r1, l2, r2), line_overlap(l2, r2, l1, r1));
			l1 = rst[i][0].timestamp;
			r1 = rst[i][rst[i].size() - 1].timestamp;
			l2 = rst2[j][0].timestamp;
			r2 = rst2[j][rst2[j].size() - 1].timestamp;
			float overlapping2 = max(line_overlap(l1, r1, l2, r2), line_overlap(l2, r2, l1, r1));
			if (overlapping1 >= gaplimit*0.8 && overlapping2 >= timelimit*0.8)
				//�ϲ�
			{
				vector< _ipid_build> ipid_sequence;
				int ii = 0, jj = 0;
				while (true)
				{
					if (rst[i][ii].ipid <= rst2[j][jj].ipid)
					{
						if (ipid_sequence.empty() || rst[i][ii].ipid != ipid_sequence[ipid_sequence.size() - 1].ipid)
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
		if (flag == 0)
		{
			rst2.push_back(rst[i]);
		}
	}

	//�ϲ�֮��,�ٰ���Щ̫�̵�ɾ����
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
	//�ٰ���Щout_of_orderռ��̫���ȥ��
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
				break;
			}
		}
		if (flag == 0)
		{
			break;
		}
	}
	return rst2;
}

vector < vector< _tcp_sequence_build > >BaseTool::construct_tcp_sequences(vector<_tcp_sequence_build> & tcp_seq_data)
//����tcp_seqԭʼ����,����tcp_seq����
{
	long timelimit = 100;
	u_short gaplimit = 1460;//mtu��С
	long MemberCri = 5;
	long MemberCri2 = 50;

	vector< vector<_tcp_sequence_build> >tcpseq_sequences;
	while (!tcpseq_sequences.empty())
	{
		tcpseq_sequences.pop_back();
	}
	for (int i = 0; i < tcp_seq_data.size(); i++)
	{
		u_short tcp_seq = tcp_seq_data[i].tcp_sequence;
		long timestamp = tcp_seq_data[i].timestamp;
		unsigned int relative_id = tcp_seq_data[i].relative_id;
		bool flag = 0;
		for (int j = 0; j < tcpseq_sequences.size(); j++)
		{
			auto ipid_diff = (tcp_seq - tcpseq_sequences[j][tcpseq_sequences[j].size() - 1].tcp_sequence) % 65536;
			while (ipid_diff<0)
			{
				ipid_diff += 65536;
			}
			auto timestamp_diff = timestamp - tcpseq_sequences[j][tcpseq_sequences[j].size() - 1].timestamp;
			if ((ipid_diff < gaplimit) && (ipid_diff >= 0) && (timestamp_diff < timelimit) && (timestamp_diff >= 0))
			{
				tcpseq_sequences[j].push_back({tcp_seq,timestamp,relative_id});
				flag = 1;
				break;
			}
		}
		if (flag == 0)
		{
			vector<_tcp_sequence_build> *tcp_seq_sequence = new vector< _tcp_sequence_build>;
			(*tcp_seq_sequence).push_back({ tcp_seq, timestamp,relative_id });
			tcpseq_sequences.push_back(*tcp_seq_sequence);
		}
	}
	vector< vector<_tcp_sequence_build> > rst;
	for (int i = 0; i < tcpseq_sequences.size(); i++)
		//����̫�̵�
	{
		if (tcpseq_sequences[i].size() >= MemberCri)
		{
			rst.push_back(tcpseq_sequences[i]);
		}
	}

	//�������������ص���,���кϲ�,�̵ĺϲ�����������ȥ
	vector < vector<_tcp_sequence_build> > rst2;
	rst2.push_back(rst[0]);
	for (int i = 1; i < rst.size(); i++)
	{
		bool flag = 0;
		for (int j = 0; j < rst2.size(); j++)
		{
			float l1 = rst[i][0].tcp_sequence;
			float r1 = rst[i][rst[i].size() - 1].tcp_sequence;
			float l2 = rst2[j][0].tcp_sequence;
			float r2 = rst2[j][rst2[j].size() - 1].tcp_sequence;
			float overlapping1 = max(line_overlap(l1, r1, l2, r2), line_overlap(l2, r2, l1, r1));
			l1 = rst[i][0].timestamp;
			r1 = rst[i][rst[i].size() - 1].timestamp;
			l2 = rst2[j][0].timestamp;
			r2 = rst2[j][rst2[j].size() - 1].timestamp;
			float overlapping2 = max(line_overlap(l1, r1, l2, r2), line_overlap(l2, r2, l1, r1));
			if (overlapping1 >= gaplimit*0.8 && overlapping2 >= timelimit*0.8)
				//�ϲ�
			{
				vector< _tcp_sequence_build> ipid_sequence;
				int ii = 0, jj = 0;
				while (true)
				{
					if (rst[i][ii].tcp_sequence <= rst2[j][jj].tcp_sequence)
					{
						if (ipid_sequence.empty() || rst[i][ii].tcp_sequence != ipid_sequence[ipid_sequence.size() - 1].tcp_sequence)
						{
							ipid_sequence.push_back(rst[i][ii]);
						}
						ii++;
					}
					else
					{
						if (ipid_sequence.empty() || rst2[j][jj].tcp_sequence != ipid_sequence[ipid_sequence.size() - 1].tcp_sequence)
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
					if (rst[i][ii].tcp_sequence != ipid_sequence[ipid_sequence.size() - 1].tcp_sequence)
					{
						ipid_sequence.push_back(rst[i][ii]);
					}
					ii++;
				}
				while (ipid_sequence.empty() || jj < rst2[j].size())
				{
					if (rst2[j][jj].tcp_sequence != ipid_sequence[ipid_sequence.size() - 1].tcp_sequence)
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
		if (flag == 0)
		{
			rst2.push_back(rst[i]);
		}
	}

	//�ϲ�֮��,�ٰ���Щ̫�̵�ɾ����
	while (true)
	{

		bool flag = 0;
		for (vector< vector< _tcp_sequence_build > >::iterator p = rst2.begin(); p != rst2.end(); p++)
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
	//�ٰ���Щout_of_orderռ��̫���ȥ��
	while (true)
	{
		bool flag = 0;
		for (vector< vector< _tcp_sequence_build> >::iterator p = rst2.begin(); p != rst2.end(); p++)
		{
			int out_of_order_count = 0;
			for (int j = 0; j < p->size() - 1; j++)
			{
				auto diff = ((*p)[j + 1].tcp_sequence - (*p)[j].tcp_sequence);
				if (diff != 0 && diff != 1)
				{
					out_of_order_count++;
				}
			}
			if (out_of_order_count>p->size()*0.5)
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
	return rst2;
}


set<int> set_interact(const set<int>& s1, const set<int> & s2)
{
	set<int> rst_set;
	rst_set.clear();
	set<int>::iterator it1 = s1.begin();
	set<int>::iterator it2 = s2.begin();
	for (; it1 != s1.end() && it2 != s2.end();)
	{
		if (*it1 < *it2)
		{
			it1++;
		}
		else if (*it1>*it2)
		{
			it2++;
		}
		else
		{
			rst_set.insert(*it1);
			it1++, it2++;
		}
	}
	return rst_set;
}

vector< vector<int> >BaseTool::associate_ipidseq_tcpseqs(const vector< vector< _ipid_build>> & ipid_sequences, const vector< vector< _tcp_sequence_build> > & tcp_sequences)
//��ipid���к�tcp_seq���й�������.�����ķ����μ����� counting nated hosts by observing tcp ip field behavior.
/*
�����ı�׼:
rst[i][j]=k
��ʾ tcp_sequences[k]���г���50%��Ԫ������ipid_sequences[i]��ĳ��ipid ����ͬһ�����ݱ�
*/
{
	vector< vector<int> > associate_rst;
	associate_rst.clear();
	vector< set<int> > ipid_sequences_relative_id_set;//ipid_sequences�����id����
	vector< set<int>> tcp_sequences_relateive_id_set;//tcp_sequences�����id����
	for (int i = 0; i < ipid_sequences.size(); i++)
	{
		associate_rst.push_back(vector<int>());
		ipid_sequences_relative_id_set.push_back(set<int>());
		for (int j = 0; j < ipid_sequences[i].size(); j++)
		{
			ipid_sequences_relative_id_set[i].insert(ipid_sequences[i][j].relative_id);
		}
	}
	for (int i = 0; i < tcp_sequences.size(); i++)
	{
		tcp_sequences_relateive_id_set.push_back(set<int>());
		for (int j = 0; j < tcp_sequences[i].size(); j++)
		{
			tcp_sequences_relateive_id_set[i].insert(tcp_sequences[i][j].relative_id);
		}
	}
	for (int i = 0; i < tcp_sequences.size(); i++)
	{
		for (int j = 0; j < ipid_sequences.size(); j++)
		{
			auto interact = set_interact(tcp_sequences_relateive_id_set[i], ipid_sequences_relative_id_set[j]);
			if (interact.size() >= tcp_sequences_relateive_id_set[i].size()*0.5)
			{
				associate_rst[j].push_back(i);
			}
		}
	}
	return associate_rst;
}

vector< vector<_tcp_srcport_build>> BaseTool::construct_tcpsrcport_sequences(vector<_tcp_srcport_build> & tcp_srcport_data)
{
	long timelimit = 512;
	u_short gaplimit =256;
	long MemberCri = 5;
	long MemberCri2 = 100;

	vector< vector<_tcp_srcport_build> >tcp_srcport_sequences;
	while (!tcp_srcport_sequences.empty())
	{
		tcp_srcport_sequences.pop_back();
	}
	for (int i = 0; i < tcp_srcport_data.size(); i++)
	{
		u_short tcp_seq = tcp_srcport_data[i].srcport;
		long timestamp = tcp_srcport_data[i].timestamp;
		unsigned int relative_id = tcp_srcport_data[i].relative_id;
		bool flag = 0;
		int min_diff = 0x0fffffff;
		int index = -1;
		if (tcp_seq == 44140)
		{
			printf("debug....\n");
		}
		for (int j = 0; j < tcp_srcport_sequences.size(); j++)
		{
			for (int k = 0; k < tcp_srcport_sequences[j].size(); k++)
			{

				auto ipid_diff = abs(tcp_seq - tcp_srcport_sequences[j][k].srcport);//������һ������,���ǲ������ҵ�̫����
				auto time_diff = (timestamp - tcp_srcport_sequences[j][k].timestamp);
				if (time_diff >= 0 && ipid_diff>=0 && ipid_diff< min_diff && ipid_diff < gaplimit &&time_diff < timelimit)
				{
					min_diff = ipid_diff;
					index = j;
				}
			}
		}
		if (index==-1)
		{
			vector<_tcp_srcport_build> *tcp_seq_sequence = new vector< _tcp_srcport_build>;
			(*tcp_seq_sequence).push_back({ tcp_seq, timestamp, relative_id });
			tcp_srcport_sequences.push_back(*tcp_seq_sequence);
		}
		else
		{

				tcp_srcport_sequences[index].push_back({ tcp_seq, timestamp, relative_id });

		}
	}
	vector< vector<_tcp_srcport_build> > rst;
	for (int i = 0; i < tcp_srcport_sequences.size(); i++)
		//����̫�̵�
	{
		if (tcp_srcport_sequences[i].size() >= MemberCri2)
		{
			rst.push_back(tcp_srcport_sequences[i]);
		}
	}
	return rst;
}

vector<_packet_statics_feature> BaseTool::abstract_statics_feature(map<unsigned int, vector<_packet_chunk_>> * p_packets, unsigned int srcip, int timegap,unsigned char device_type)
//�̶�IP,��ȡ���IP��ص�������ͳ������,��timegapΪһ�����������ȡ.��������p_packets�������timegap,��ô���ؽ��Ҳ��������vector<_packet_statics_feature>
//Ĭ��timegapΪһ��Сʱ
{
	vector< _packet_statics_feature>  statics_features;
	vector<_packet_chunk_>& packets = (*p_packets)[srcip];
	for (int i = 0; i < packets.size(); i++)
	{

		int index = packets[i].timestamp / timegap;
		while (statics_features.size() <= index)
			//������,���Ƚ���
		{

			_packet_statics_feature* feature = new _packet_statics_feature();
			statics_features.push_back(*feature);
		}
		if (statics_features[index].ip==0)
			//�����ǿյ�,��û�н�����Ч��ֵ
		{
			statics_features[index].ip = srcip;
			statics_features[index].device_type = device_type;
			statics_features[index].start_timestamp = packets[i].timestamp;
			statics_features[index].oicq_set = new set<unsigned int >();
			statics_features[index].srcport_seq = new vector<unsigned short int>();
			statics_features[index].timestamp_seq = new vector<unsigned int>();
			statics_features[index].ip_set = new set<unsigned int>();
			statics_features[index].ttl_set = new set<unsigned char>();
		}
		if (packets[i].timestamp < statics_features[index].start_timestamp)
		{
			statics_features[index].start_timestamp = packets[i].timestamp;
		}
		if (packets[i].timestamp>statics_features[index].end_timestamp)
		{
			statics_features[index].end_timestamp = packets[i].timestamp;
		}
		if (packets[i].flag == 0)
		{
			statics_features[index].numInPkt++;
			statics_features[index].numInByte += packets[i].byte_length;
		}
		else if (packets[i].flag == 1)
			//���ڰ�
		{
			statics_features[index].numOutPkt++;
			statics_features[index].numOutByte += packets[i].byte_length;
			statics_features[index].ip_set->insert(packets[i].dstip);

			if ((packets[i].utility_flag & OICQFLAG) == OICQFLAG)
			{
				statics_features[index].oicq_set->insert(packets[i].oicq_number);
			}
			if ((packets[i].utility_flag & SYNFLAG) == SYNFLAG && (packets[i].utility_flag& TCPFLAG) == TCPFLAG)
			{
				statics_features[index].srcport_seq->push_back(packets[i].srcport);
				statics_features[index].ttl_set->insert(packets[i].ttl);
			}
			if ((packets[i].utility_flag & DNSFLAG) == DNSFLAG)
			{
				statics_features[index].numDNSReq++;
			}
			if ((packets[i].utility_flag & SYNFLAG) == SYNFLAG)
			{
				statics_features[index].numSYN++;
			}
			statics_features[index].timestamp_seq->push_back(packets[i].timestamp);
		}
		if ((packets[i].utility_flag & TCPFLAG) == TCPFLAG)
		{
			statics_features[index].numTCP++;
		}
		if ((packets[i].utility_flag & UDPFLAG) == UDPFLAG)
		{
			statics_features[index].numUDP++;
		}
		if ((packets[i].utility_flag & HTTPFLAG) == HTTPFLAG)
		{
			statics_features[index].numHTTP++;
		}
		if ((packets[i].utility_flag & FINFLAG) == FINFLAG)
		{
			statics_features[index].numFIN++;
		}
		if ((packets[i].utility_flag & RSTFLAG) == RSTFLAG)
		{
			statics_features[index].numRST++;
		}
		//if (i == 77)
		//���ֶ�λ���Ե�
		//{
		//	printf("%d", i);
		//}

	}
	//��������
	set<int> dropIndex;
	for (int i = 0; i<statics_features.size();i++)
	{
		if (abs(statics_features[i].end_timestamp - statics_features[i].start_timestamp) < timegap*0.5)
		{
			dropIndex.insert(i);
			continue;
		}
		statics_features[i].numOICQ = statics_features[i].oicq_set->size();
		delete statics_features[i].oicq_set;
		statics_features[i].numIP = statics_features[i].ip_set->size();
		delete statics_features[i].ip_set;
		statics_features[i].numTTL = statics_features[i].ttl_set->size();
		delete statics_features[i].ttl_set;
		statics_features[i].diff_udp_tcp = abs(statics_features[i].numUDP - statics_features[i].numTCP)*1.0 / (0.000001+statics_features[i].numInPkt + statics_features[i].numOutPkt);
		//����srcport�ķ���
		double avg = 0;
		double sum = 0;
		for (int j = 0; j < statics_features[i].srcport_seq->size(); j++)
		{
			sum += (*statics_features[i].srcport_seq)[j];
		}
		avg = sum / (0.000001+statics_features[i].srcport_seq->size());
		sum = 0;//ƽ�����
		for (int j = 0; j < statics_features[i].srcport_seq->size(); j++)
		{
			sum += pow((*statics_features[i].srcport_seq)[j]-avg,2);
		}
		avg = sum / (0.000001+statics_features[i].srcport_seq->size());

		statics_features[i].std_srcport = sqrt(avg);
		delete statics_features[i].srcport_seq;
		//�������ʱ��
		set<unsigned int> timestamp_set;
		for (int ii = 0; ii < statics_features[i].timestamp_seq->size(); ii++)
		{
			timestamp_set.insert((*statics_features[i].timestamp_seq)[ii]);
		}
		statics_features[i].idle_time = (statics_features[i].end_timestamp - statics_features[i].start_timestamp) - timestamp_set.size();
		statics_features[i].idle_time_rate = statics_features[i].idle_time / (0.00001+(statics_features[i].end_timestamp - statics_features[i].start_timestamp));
		//�����������(��ֵС�ڵ���2)æµʱ��,ʹ��DP�㷨
		int * count_array = (int *)malloc(sizeof(int)*(timestamp_set.size()));
		int ii = 0;
		statics_features[i].max_busy_time = 0;
		unsigned int last = 0;
		for (set<unsigned int>::iterator p = timestamp_set.begin(); p != timestamp_set.end(); ii++,p++)
		{
			if (ii == 0)
			{
				count_array[ii] = 1;
				last = *p;
				continue;
			}
			if ((*p - last) <= 2)
			{
				count_array[ii] = count_array[ii - 1] + *p - last;
			}
			else
			{
				count_array[ii] = 1;
			}
			last = *p;
			if (count_array[ii] > statics_features[i].max_busy_time)
			{
				statics_features[i].max_busy_time = count_array[ii];
			}

		}
		free(count_array);
		delete statics_features[i].timestamp_seq;
	}

	vector< _packet_statics_feature>  statics_features_ret;
	for (int i = 0; i < statics_features.size(); i++)
	{
		if (dropIndex.find(i) != dropIndex.end())
		{
			continue;
		}
		statics_features_ret.push_back(statics_features[i]);
	}
	return statics_features_ret;
}
map<unsigned int, vector < _packet_chunk_> >* BaseTool::cluster_raw_pakcets_online(pcap_t *pt,int timegap)
//���߻�ȡ����,����Դip�����ռ�
//2018-03-22
{
	static unsigned int relative_id = 0;
	map<unsigned int, vector< _packet_chunk_> >* prst = new map<unsigned int, vector< _packet_chunk_> >;
	while (!prst->empty())
		//���
	{
		prst->clear();
	}
	if (pt == NULL)
	{
		pt = this->pcapt;
	}
	this->start_timestamp = -1;
	while (true)
	{
		vector<_packet> pkt = this->getNextPacket(pt);
		relative_id = (relative_id + 1) % 0xFFFFFFFF;
		if (pkt.size())
		{
			_packet_chunk_ packet_info;

			packet_info.timestamp = pkt[0].timestamp;
			if (!(packet_info.timestamp > 0  && packet_info.timestamp<timegap ))
			{
				free(pkt[0].data);
				break;
			}
			int ip_flag = (*(u_short*)(pkt[0].data + 12));
			if (ip_flag != 0x0008)//��ipЭ��
			{
				continue;
			}
			ip_header *ih;
			udp_header *udp;
			tcp_header *tcp;
			u_int ip_len;
			ih = (ip_header*)(pkt[0].data + 14);//����̫��ͷƫ��
			/*
			�ѹ㲥���Ĺ���
			*/
			//if (ih->daddr == 0xffffffff || ih->saddr == 0xffffffff)
			//{
			//	continue;
			//}

			//if (ih->daddr&0xff000000==0xff000000||ih->saddr&0xff000000==0xff000000)
			//	//�ڲ��Ĺ㲥����
			//{
			//	continue;
			//}
			little_endian2big_endian((u_char*)&(ih->identification), 2, (u_char*)&(packet_info.ipid));
			packet_info.ttl = ih->ttl;
			packet_info.byte_length = pkt[0].len - 14;
			packet_info.relative_id = relative_id;
			if (ih->proto == 6)
				//tcpЭ��,��ȡtcp sequence
			{
				packet_info.utility_flag |= TCPFLAG;
				tcp = (tcp_header*)(pkt[0].data + 14 + 20);
				unsigned short srcport;
				unsigned short dstport;
				little_endian2big_endian((u_char*)&(tcp->sequence), 4, (u_char*)&(packet_info.tcp_sequecnce));

				little_endian2big_endian((u_char*)&(tcp->sport), 2, (u_char*)&(srcport));

				little_endian2big_endian((u_char*)&(tcp->dport), 2, (u_char*)&(dstport));
				packet_info.srcport = srcport;
				if (srcport == 80 || srcport == 443 || dstport == 80 || srcport == 443)
					//http ����
				{
					packet_info.utility_flag |= HTTPFLAG;
				}
				if (tcp->flag & 0x01)
					//fin ����
				{
					packet_info.utility_flag |= FINFLAG;
				}
				if (tcp->flag & 0x02)
					//SYN����
				{
					packet_info.utility_flag |= SYNFLAG;
				}
				if (tcp->flag & 0x04)
					//reset ����
				{
					packet_info.utility_flag |= RSTFLAG;
				}
			}
			else if (ih->proto == 17)
				//udpЭ��
			{
				packet_info.utility_flag |= UDPFLAG;
				udp = (udp_header*)(pkt[0].data + 14 + 20);
				unsigned short srcport, dstport;
				little_endian2big_endian((u_char*)&(udp->sport), 2, (u_char*)&(srcport));
				little_endian2big_endian((u_char*)&(udp->dport), 2, (u_char*)&(dstport));
				if (srcport == 53 || dstport == 53)
				{
					packet_info.utility_flag |= DNSFLAG;
				}
				if (srcport == 8000 || dstport == 8000)

				{
					unsigned char * pdata = pkt[0].data + 14 + 20 + sizeof(udp_header);
					if (pdata[0] == 0x02)
						//oicqЭ��
					{
						little_endian2big_endian(pdata + 6, sizeof(unsigned int), (unsigned char *)&packet_info.oicq_number);
					}
				}
			}

			//���Ͼ��Ѿ��������
			packet_info.dstip = ih->daddr;
			//��src ip ��˵,������ǳ�ȥ�İ�
			packet_info.flag = 1;
			if (prst->find(ih->saddr) != prst->end())
				//�Ѿ��ҵ���,������ݲ���
			{
				(*prst)[ih->saddr].push_back(packet_info);
			}
			else
			{
				(*prst)[ih->saddr].push_back(packet_info);
			}
			//��dst ip��˵,������ǽ����İ�
			packet_info.dstip = ih->saddr;
			packet_info.flag = 0;
			(*prst)[ih->daddr].push_back(packet_info);
			//�ͷű���ռ�õ��ڴ�
			free(pkt[0].data);
		}
		else
		{
			break;
		}

	}
	return prst;
}

