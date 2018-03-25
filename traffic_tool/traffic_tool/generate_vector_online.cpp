#include <stdio.h>
#include <stdlib.h>
#include "BaseTool.h"
#include <inaddr.h>
#include <string.h>
#if 1
int main()
{
	char * ip = "172.16.30.34";
	char device_type = 0x01; //host
	char filter[256] = { 0 };
	//sprintf(filter, "host %s ", ip);
	BaseTool pkt("\\Device\\NPF_{286C61F8-4979-4EF5-8087-CE3DFB534602}",filter);
	char buf[256] = { 0 };
	while (true)
	{
		auto prst = pkt.cluster_raw_pakcets_online(0, 1 * 60);
		auto statics_feature = pkt.abstract_statics_feature(prst, inet_addr(ip), 60 * 1, device_type);
		for (int i = 0; i < statics_feature.size(); i++)
		{
			statics_feature[i]._vectorize(buf, 256);
			sprintf("%s", buf);
		}

	}
}
#endif