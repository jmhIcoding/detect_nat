#include "request.h"
#include "json.h"
#include <iostream>
#if 1
int main()
{
	json j;
	std::cout << typeid(_string).name() << endl;
	j.loads("{\"192.168.1.234\":0.8}");
	printf("%f\n", j.operator[]<float>("192.168.1.234"));
	j.setdefault("192.168.199.234", "1 2 3 4 5 6 0.5");
	printf("%s \n", j.operator[]<char *>("192.168.199.234"));
	system("pause");
	return 0;
}
#endif