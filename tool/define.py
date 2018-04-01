__author__ = 'dell'
CPORT=10000		#//	C/C++使用的端口
PPORT=10001		#//	Python使用的端口

BUFSIZE=4096
#//消息类型定义
PREDICTREQ=0x01 #//	预测请求
PREDICTRES=0x02	#//	预测响应
SIZEUPLOAD=0x03 #//	上传规模检测结果