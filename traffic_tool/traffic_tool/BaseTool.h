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
	//����ipid_sequencesʹ��
{
	u_short ipid;
	long timestamp;
	unsigned int relative_id;
};
struct _tcp_sequence_build
	//tcp ���к� ���еĽ���ʹ��
{
	unsigned int tcp_sequence;
	int timestamp;
	unsigned int relative_id;
};
struct _tcp_srcport_build
	//tcp Դ�˿� ���еĽ���ʹ��
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
	//����Դip��ַ�ۺϺ�,���ݰ��Ľṹ.
{
	unsigned char flag;//���ݰ���ʾλ,��Ҫ���ڱ�ʾ�����ݰ������ݰ��ǳ�,���������ݰ�. 0:�� 1:��
	unsigned int byte_length;//IP���ݰ��ĳ���,����ͷ
	unsigned char utility_flag;//���ڱ�ʾ�����ݰ���udp,tcp,http,dns,oicq
	/*
	utility_flag:
	(��λ)	bit				����
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
	unsigned int timestamp;//ʱ���
	unsigned short ipid;//ipid�ֶ�
	unsigned int tcp_sequecnce;//tcp ���к�
	unsigned short srcport;//tcp ��Դ�˿�,ע��,udp��Դ�˿ڲ�ʹ��.
	unsigned int dstip;//Ŀ��ip��ַ
	unsigned char ttl;//���ĵ�ttl�ֶ�;
	unsigned int oicq_number;//qq��,��Ҫ��-1ȥ��
	unsigned int relative_id;//��Ե�id��,���ڱ�ʾÿһ�����������ݰ�,��Ҫ�����ع�ipid,tcp sequence,tcp source port����.
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
	//���ù�����
	vector< _packet> getPackets(pcap_t * pt = NULL);
	//��ȡȫ������,��Ҫ����ͨ���ļ���ȡ����
	vector< _packet> getNextPacket(pcap_t * pt = NULL);
	//һ��һ���Ļ�ȡ����
	~BaseTool();
	int getpayload_offset(unsigned char *pkt_data);
	//�õ�udp��tcp���غ�ƫ����
	vector<_packet_host_cont> get_host_count_data(pcap_t * pt=NULL,int ipaddr=0);
	//�ӱ����л�ȡ����IP��ipid,tcp seq,Դ�˿ں�.���������һ��vector����

	static void little_endian2big_endian(u_char * srcbuf, int len, u_char * dstbuf)
	{
		for (int i = 0; i < len; i++)
		{
			dstbuf[len - 1 - i] = srcbuf[i];
		}
	}
	static vector< vector<_ipid_build> > construct_ipid_sequence(vector<_packet_host_cont>& _host_count,int timelen=0);
	//����_host_count�����¼��ipid����,�ع�ipid_sequence,��ipid���ݷֳ����ɸ���ͬ�����С�
	static float line_overlap(float l1, float r1, float l2, float r2)
		//�ص��ĳ���,��Ҫ��������ȡ�����ص�
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
	map<unsigned int, vector < _packet_chunk_> >* cluster_raw_pakcets(pcap_t *pt=NULL);//��ԭʼ����,����Դip�����ռ�.
	
	vector<_ipid_build> get_ipid_data(map<unsigned int, vector<_packet_chunk_>> * p_packets, unsigned int srcip);
	//����Դip,��ȡ���е�ipidԭʼ���ݡ��������еĳ��ڱ���
	vector<_tcp_sequence_build> get_tcp_seq_data(map<unsigned int, vector<_packet_chunk_>> * p_packets, unsigned int srcip);
	//����Դip,��ȡ���е�tcp_seqԭʼ���ݡ��������еĳ��ڱ���
	vector<_tcp_srcport_build> get_tcp_srcport_data(map<unsigned int, vector<_packet_chunk_>> * p_packets, unsigned int srcip);
	//����Դip,��ȡ���е�tcp_srcportԭʼ���ݡ��������еĳ��ڱ���

	vector < vector< _ipid_build > >construct_ipid_sequences(const vector<_ipid_build> & ipid_data);
	//����ipid_buildԭʼ����,����ipid����

	vector < vector< _tcp_sequence_build > >construct_tcp_sequences(vector<_tcp_sequence_build> & tcp_seq_data);
	//����tcp_seqԭʼ����,����tcp_seq����

	vector< vector<int>> associate_ipidseq_tcpseqs(const vector< vector< _ipid_build>> & ipid_sequences, const vector< vector< _tcp_sequence_build> > & tcp_sequences);
	//��ipid���к�tcp_seq���й�������.�����ķ����μ����� counting nated hosts by observing tcp ip field behavior.

	vector< vector<_tcp_srcport_build>> construct_tcpsrcport_sequences(vector<_tcp_srcport_build> & tcp_srcport_data);
private:
	pcap_t *pcapt;
	char errBuf[PCAP_ERRBUF_SIZE];
	long start_timestamp=-1;
	map<unsigned int, vector< _packet_chunk_>> packet_chunk;
	//ip-> _packet_chunk������
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