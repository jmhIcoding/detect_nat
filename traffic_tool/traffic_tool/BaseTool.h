#pragma once
#ifndef __BASETOOLH__
#define __BASETOOLH__  0
#include <stdio.h>
#include <stdlib.h>
#include <pcap-stdinc.h>
#include <pcap.h>
#include <vector>
#include <string.h>
#include <malloc.h>
#include <map>
#include <set>
#include "define.h"
using namespace std;
struct _ipid_build
	//建立ipid_sequences使用
{
	u_short ipid;
	long timestamp;
	unsigned int relative_id;
};
struct _tcp_sequence_build
	//tcp 序列号 序列的建立使用
{
	unsigned int tcp_sequence;
	int timestamp;
	unsigned int relative_id;
};
struct _tcp_srcport_build
	//tcp 源端口 序列的建立使用
{
	unsigned short srcport;
	int timestamp;
	unsigned int relative_id;
};
struct _packet
{
	int len;
	int timestamp;
	unsigned char * data;
};
struct _packet_host_cont
{
	u_short ipid=0;
	int timestamp=0;
	u_int tcpseq=0;
	u_short srcport=0;
};
struct _packet_chunk_
	//基于源ip地址聚合后,数据包的结构.
{
	unsigned char flag;//数据包标示位,主要用于标示改数据包是数据包是出,还是入数据包. 0:入 1:出
	unsigned int byte_length;//IP数据包的长度,包括头
	unsigned char utility_flag;//用于标示该数据包是udp,tcp,http,dns,oicq
	/*
	utility_flag:
	(高位)	bit				含义
	|*|*|*|*|*|*|*|*|
	|1|*|*|*|*|*|*|*| 		tcp
	|*|1|*|*|*|*|*|*|		udp
	|*|*|1|*|*|*|*|*|		http
	|*|*|*|1|*|*|*|*|		dns
	|*|*|*|*|1|*|*|*|		oicq
	|*|*|*|*|*|1|*|*|		FIN
	|*|*|*|*|*|*|1|*|		SYN
	|*|*|*|*|*|*|*|1|		RST
	*/
	unsigned int timestamp;//时间戳
	unsigned short ipid;//ipid字段
	unsigned int tcp_sequecnce;//tcp 序列号
	unsigned short srcport;//tcp 的源端口,注意,udp的源端口不使用.
	unsigned int dstip;//目的ip地址
	unsigned char ttl;//报文的ttl字段;
	unsigned int oicq_number;//qq号,需要将-1去掉
	unsigned int relative_id;//相对的id号,用于标示每一个独立的数据包,主要用于重构ipid,tcp sequence,tcp source port序列.
	_packet_chunk_():
		flag(0xFF), byte_length(0), utility_flag(0), timestamp(0), ipid(0), tcp_sequecnce(0), dstip(0), srcport(0), ttl(0), oicq_number(-1), relative_id(0)
	{
		;
	}
};

class BaseTool
{
public:
	static void display(unsigned char * pkt_data,int len,int nextline=16);
public:
	BaseTool();
	BaseTool(const char *pcapfilename);
	void setFilter(char *FilterString, pcap_t * pt = NULL);
	//设置过滤器
	vector< _packet> getPackets(pcap_t * pt = NULL);
	//获取全部报文,主要用于通过文件获取报文
	vector< _packet> getNextPacket(pcap_t * pt = NULL);
	//一个一个的获取报文
	~BaseTool();
	int getpayload_offset(unsigned char *pkt_data);
	//得到udp或tcp的载荷偏移量
	vector<_packet_host_cont> get_host_count_data(pcap_t * pt=NULL,int ipaddr=0);
	//从报文中获取给定IP的ipid,tcp seq,源端口号.结果保存在一个vector里面

	static void little_endian2big_endian(u_char * srcbuf, int len, u_char * dstbuf)
	{
		for (int i = 0; i < len; i++)
		{
			dstbuf[len - 1 - i] = srcbuf[i];
		}
	}
	static vector< vector<_ipid_build> > construct_ipid_sequence(vector<_packet_host_cont>& _host_count,int timelen=0);
	//根据_host_count里面记录的ipid序列,重构ipid_sequence,将ipid数据分成若干个不同的序列。
	static float line_overlap(float l1, float r1, float l2, float r2)
		//重叠的长度,需要运算两次取最大的重叠
	{
		if (r1 <= l2) return 0;
		if (l2 >= l1 && r1 <= r2)
		{
			return r1 - l2;
		}
		if (l2 >= l1 && r1 >= r2)
		{
			return r2 - l2;
		}
		return -1;
	}
	map<unsigned int, vector < _packet_chunk_> >* cluster_raw_pakcets(pcap_t *pt=NULL);//对原始报文,基于源ip进行收集.
	
	vector<_ipid_build> get_ipid_data(map<unsigned int, vector<_packet_chunk_>> * p_packets, unsigned int srcip);
	//给定源ip,提取其中的ipid原始数据。过滤其中的出口报文
	vector<_tcp_sequence_build> get_tcp_seq_data(map<unsigned int, vector<_packet_chunk_>> * p_packets, unsigned int srcip);
	//给定源ip,提取其中的tcp_seq原始数据。过滤其中的出口报文
	vector<_tcp_srcport_build> get_tcp_srcport_data(map<unsigned int, vector<_packet_chunk_>> * p_packets, unsigned int srcip);
	//给定源ip,提取其中的tcp_srcport原始数据。过滤其中的出口报文

	vector < vector< _ipid_build > >construct_ipid_sequences(const vector<_ipid_build> & ipid_data);
	//根据ipid_build原始数据,构建ipid序列

	vector < vector< _tcp_sequence_build > >construct_tcp_sequences(vector<_tcp_sequence_build> & tcp_seq_data);
	//根据tcp_seq原始数据,构建tcp_seq序列

	vector< vector<int>> associate_ipidseq_tcpseqs(const vector< vector< _ipid_build>> & ipid_sequences, const vector< vector< _tcp_sequence_build> > & tcp_sequences);
	//将ipid序列和tcp_seq序列关联起来.关联的方法参见文献 counting nated hosts by observing tcp ip field behavior.

	vector< vector<_tcp_srcport_build>> construct_tcpsrcport_sequences(vector<_tcp_srcport_build> & tcp_srcport_data);
private:
	pcap_t *pcapt;
	char errBuf[PCAP_ERRBUF_SIZE];
	long start_timestamp=-1;
	map<unsigned int, vector< _packet_chunk_>> packet_chunk;
	//ip-> _packet_chunk的序列
};
/* 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	u_int  saddr;      // Source address
	u_int  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;

/*TCP header*/
typedef struct tcp_header
{
	u_short sport;
	u_short dport;
	u_int sequence;
	u_int acknum;
	u_char tcpHeader_reserve;
	u_char flag;
	u_short window_size;
	u_short crc;
	u_short agency_point;
	u_int choice;
	u_char *appendix;
};

#endif