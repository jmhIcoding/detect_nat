vectorize_net.out : BaseTool.o NetTool.o main.o 
	g++ -o vectorize_net.out BaseTool.o NetTool.o  main.o  -g -lpcap -lpthread  -w
BaseTool.o : BaseTool.cpp define.h
	g++ -c BaseTool.cpp define.h -g -lpcap  -w	
NetTool.o : NetTool.cpp define.h 
	g++ -c NetTool.cpp -g -lpcap -lpthread  -w 
main.o : NetTest.cpp define.h 
	g++ -c NetTest.cpp -g -lpcap -lpthread -w -o main.o
clean :
	rm main.o BaseTool.o NetTool.o vectorize_net.out
#install :
#	cp vectorize_online.out /usr/bin/vectorize_online
#uninstall :
#	rm /usr/bin/vectorize_online
