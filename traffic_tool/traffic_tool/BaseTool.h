#pragma once
#ifndef __BASETOOLH__
#define __BASETOOLH__  0
#ifdef _WIN32
#define WINDOWS
#endif
#ifdef __linux__
#include <arpa/inet.h>
#define LINUX
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef WINDOWS
#include <pcap-stdinc.h>
#include <inaddr.h>
#endif
#include <pcap.h>
#include <vector>
#include <string.h>
#include <malloc.h>
#include <map>
#include <set>
#include <math.h>
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
struct _packet_statics_feature
{
	unsigned int ip;			//统计对象
	unsigned char device_type;//设备类型: 0x01:单机设备	0x02:NAT设备 0x00:未知
	int start_timestamp;		//统计的起始时间戳
	int end_timestamp;			//统计的结束时间戳
								// start_timestamp~end_timestamp为统计时段
	int numInPkt;				//统计时段内流入的IP数据包个数
	int numInByte;				//流入的字节数
	int numOutPkt;					//流出的IP数据包个数
	int numOutByte;				//流出的字节数
	int numHTTP;				//HTTP(s)数据包个数
	int numTCP;					//TCP数据包个数
	int	numUDP;					//UDP数据包个数
	int numDNSReq;				//发出的DNS请求个数
	int numSYN;					//发出的SYN个数
	int numRST;					//RST报文个数（与流向无关)
	int numFIN;					//FIN报文个数（与流向无关)
	int numIP;					//与多少个不同的IP进行通信
	float idle_time;			//累计空闲时长
	float max_busy_time;		//最大连续忙碌时长
	float idle_time_rate;		//空闲时间占比:idle_time/(end_timestamp-start_timestamp)
	float diff_udp_tcp;			//abs(numTCP-numUDP)/(numInPkt+numOutPkt)
	int numOICQ;				//OICQ协议中,不同QQ号的个数
	set<unsigned int>* oicq_set;//oicq qq号集合
	int numTTL;					//发出的IP数据中有多少个不同的TTL值
	double std_srcport;			//发出的TCP SYN报文中 srcport的标准差
	vector<unsigned short>* srcport_seq;//发出的TCP SYN srcport集合
	vector<unsigned int> * timestamp_seq;//包到达时间序列,用于计算空闲时间
	set<unsigned int >* ip_set;
	set<unsigned char > * ttl_set;
	_packet_statics_feature() :
		ip(0), device_type(0x00),
		start_timestamp(0), end_timestamp(0),
		numInPkt(0), numInByte(0), numOutPkt(0), numOutByte(0), numHTTP(0), numTCP(0), numUDP(0), numDNSReq(0), numSYN(0), numFIN(0), numRST(0), numIP(0), numOICQ(0), numTTL(0),
		idle_time(0), max_busy_time(0), idle_time_rate(0), std_srcport(0), diff_udp_tcp(0),
		oicq_set(NULL), srcport_seq(NULL),timestamp_seq(NULL),ip_set(NULL),ttl_set(NULL)
	{
		;
	}

	//~_packet_statics_feature()
	//{
	//	if(oicq_set)
	//	{
	//		delete oicq_set;
	//	}
	//	if(srcport_seq)
	//	{
	//		delete srcport_seq;
	//	}
	//	if(timestamp_seq)
	//	{
	//		delete timestamp_seq;
	//	}
	//	if(ip_set)
	//	{
	//		delete ip_set;
	//	}
	//	if(ttl_set)
	//	{
	//		delete ttl_set;
	//	}
	//}
	void display()
	{
		in_addr addr;
#ifdef _WIN32
		addr.S_un.S_addr = this->ip;
#endif
#ifdef __linux__
		addr.s_addr=this->ip;
#endif
		printf("IP:%s , device type:%d \n", inet_ntoa(addr), this->device_type);
		printf("start timestamp:%d, end timestamp:%d \n", start_timestamp, end_timestamp);
		printf("numInPkt:%d, numInByte:%d\n", numInPkt, numInByte);
		printf("numOutPkt:%d, numOutByte:%d \n", numOutPkt, numOutByte);
		printf("numHTTP:%d \n", numHTTP);
		printf("numTCP:%d , numUDP：%d \n", numTCP, numUDP);
		printf("numDNSReq:%d \n", numDNSReq);
		printf("numSYN:%d , numFIN:%d , numRST :%d \n", numSYN, numFIN, numRST);
		printf("numIP:%d \n", numIP);
		printf("numOICQ:%d \n", numOICQ);
		printf("numTTL:%d \n", numTTL);
		printf("idle time:%f \n", idle_time);
		printf("idle time rate:%f \n", idle_time_rate);
		printf("max busy time:%f \n", max_busy_time);
		printf("std src port:%f \n", std_srcport);
		printf("diff udp tcp:%f \n", diff_udp_tcp);
		printf("****************************************************\n");

	}
	void _vectorize(char * dst,int bufSize=512)
		//向量的格式：
		/*
		label 特征0 特征1 特征2 ....\n
		label 特征0 特征1 特征2 ....\n
		label 特征0 特征1 特征2 ....\n
		label 特征0 特征1 特征2 ....\n
		···
		···
		*/
	{
		memset(dst, 0, bufSize);
		sprintf(dst, "%d %d %d %d %d %d %d %d %d %d %d %d %d %f %f %f %f %d %d %f\n", device_type,
			numInPkt, numInByte, numOutPkt, numOutByte,
			numHTTP, numTCP, numUDP, numDNSReq,
			numSYN, numRST, numFIN,
			numIP,
			idle_time,max_busy_time, idle_time_rate,
			diff_udp_tcp,
			numOICQ,
			numTTL,
			std_srcport
			);
	}
	void vectorize(char *filename,char *mode="a")
	{
		FILE *fp = fopen(filename,mode);
		vectorize(fp);
		fclose(fp);
	}
	void vectorize(FILE * fp)
	{
		char buf[512];
		_vectorize(buf);
		printf("%s", buf);
		//display();
		fprintf(fp, buf);
	}
};


class BaseTool
{
public:
	static void display(unsigned char * pkt_data,int len,int nextline=16);
public:
	BaseTool();
	BaseTool(const char *pcapfilename);
	BaseTool(const char *interfaces, char *filters);//在线获取数据,但是需要使用filters先进行过滤
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
	
	map<unsigned int, vector < _packet_chunk_> >* cluster_raw_pakcets_online(pcap_t *pt = NULL,int timegap=60*12);//在线处理,基于源ip进行收集.
	vector<_ipid_build> get_ipid_data(map<unsigned int, vector<_packet_chunk_> > * p_packets, unsigned int srcip);
	//给定源ip,提取其中的ipid原始数据。过滤其中的出口报文
	vector<_tcp_sequence_build> get_tcp_seq_data(map<unsigned int, vector<_packet_chunk_> > * p_packets, unsigned int srcip);
	//给定源ip,提取其中的tcp_seq原始数据。过滤其中的出口报文
	vector<_tcp_srcport_build> get_tcp_srcport_data(map<unsigned int, vector<_packet_chunk_> > * p_packets, unsigned int srcip);
	//给定源ip,提取其中的tcp_srcport原始数据。过滤其中的出口报文

	vector < vector< _ipid_build > >construct_ipid_sequences(const vector<_ipid_build> & ipid_data);
	//根据ipid_build原始数据,构建ipid序列

	vector < vector< _tcp_sequence_build > >construct_tcp_sequences(vector<_tcp_sequence_build> & tcp_seq_data);
	//根据tcp_seq原始数据,构建tcp_seq序列

	vector< vector<int> > associate_ipidseq_tcpseqs(const vector< vector< _ipid_build> > & ipid_sequences, const vector< vector< _tcp_sequence_build> > & tcp_sequences);
	//将ipid序列和tcp_seq序列关联起来.关联的方法参见文献 counting nated hosts by observing tcp ip field behavior.

	vector< vector<_tcp_srcport_build> > construct_tcpsrcport_sequences(vector<_tcp_srcport_build> & tcp_srcport_data);
	//提取TCP src port 序列
	vector<_packet_statics_feature> abstract_statics_feature(map<unsigned int, vector<_packet_chunk_> > * p_packets, unsigned int srcip,int timegap=3600,unsigned char device_type=0x00);
	//固定IP,提取与该IP相关的流量的统计特征,以timegap为一个间隔进行提取.若所给的p_packets包含多个timegap,那么返回结果也会包含多个vector<_packet_statics_feature>
private:
	pcap_t *pcapt;
	char errBuf[PCAP_ERRBUF_SIZE];
	long start_timestamp=-1;
	map<unsigned int, vector< _packet_chunk_> > packet_chunk;
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
