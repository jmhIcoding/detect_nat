#ifndef __DEFINE__H
#define __DEFINE__H


#define TCPFLAG 0x80
#define UDPFLAG 0x40
#define HTTPFLAG 0x20
#define DNSFLAG 0x10
#define OICQFLAG 0x08
#define FINFLAG 0x04
#define SYNFLAG 0x02
#define RSTFLAG 0x01

#define BUFSIZE 4096
#define CPORT 10000		//	C/C++ʹ�õĶ˿� ,��C��˵����˿�ֻ����������
#define PPORT 10001		//	Pythonʹ�õĶ˿�,��C��˵����˿�ֻ��������
//��Ϣ���Ͷ���
#define PREDICTREQ 0x01 //	Ԥ������
#define PREDICTRES 0x02	//	Ԥ����Ӧ
#define SIZEUPLOAD 0x03 //	�ϴ���ģ�����
#endif