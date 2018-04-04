#pragma once
#include <math.h>
const double m = 256;
const double eupsiten = 0.0000000001;
#include <map>
using namespace std;
map<int, double> H_mu_table;
double hu(int N)
{
	double sum = 0;
	if (H_mu_table.find(N) == H_mu_table.end())
	{

		double c = N / m;

		int iteration = 1.09*c + 240;
		sum = log2(m) + log2(c) + 0.004;
		double e = 2.7182818;
		double e_c = pow(e, -c);
		double s = 0;
		for (int j = 1; j < iteration; j++)
		{
			double c_j_1 = 1;
			for (int i = 1; i < j; i++)
			{
				c_j_1 *= c / i;
			}
			s += c_j_1*log2(j*1.0);
		}
		sum -= e_c*s;
		H_mu_table[N] = sum;
	}
	else
	{
		sum = H_mu_table[N];
	}
		return sum;
}

double HMLE(unsigned char *data, int len)
	{
		double c[256] = { 0 };
		double f[256] = { 0 };
		double sum = 0;
		for (int i = 0; i < len; i++)
		{
			c[data[i]]++;
		}
		for (int i = 0; i < 256; i++)
		{
			f[i] = c[i] / len;
			sum += f[i] * log2(f[i]+eupsiten);
		}
		return -sum;
	}
int is_Encrypted(unsigned char * pkt_data, int len)
{
	if (len > 16)
	{
		double benchmark = hu(len);
		double hmle = HMLE(pkt_data, len);
		if (abs(benchmark - hmle) < 3*0.08)
		{
			return 1;//加密
		}
		return 0;//未加密
	}
	return -1;//长度不够
}
