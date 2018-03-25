vectorize_online.out : BaseTool.cpp generate_vector_online.cpp define.h
	g++ generate_vector_online.cpp BaseTool.cpp define.h -g -lpcap -o vectorize_online.out -w
clean :
	rm vectorize_online.out
install :
	cp vectorize_online.out /usr/bin/vectorize_online
uninstall :
	rm /usr/bin/vectorize_online
