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
#define CPORT 10000		//	C/C++使用的端口 ,对C来说这个端口只负责收数据
#define PPORT 10001		//	Python使用的端口,对C来说这个端口只负责发数据
//消息类型定义
#define PREDICTREQ 0x01 //	预测请求
#define PREDICTRES 0x02	//	预测响应
#define SIZEUPLOAD 0x03 //	上传规模检测结果
#endif