#pragma once
#include "document.h"
#include "prettywriter.h"
#include "writer.h"
#include "stringbuffer.h"
typedef char * _string;
#include <string.h>
#include <type_traits>
using namespace rapidjson;
using namespace std;
class json
{
public:
	json();
	void loads(char *str)
		//从字符串载入Json
	{
		this->doc.Parse(str);
	}
	char * dumps();
	//将目前的json保存成字符串
	template <typename T>
	T operator[](char *key)
		//通过key来读取value,T是Value的类型。可读取,可以写
	{
		if (this->doc.HasMember(key) == false)
		{
			assert("No Such Key-Value");
		}
		if (typeid(T) == typeid(int))
		{
			return this->doc[key].GetInt();
		}
		if (typeid(T) == typeid(float))
		{
			return this->doc[key].GetFloat();
		}
		if (typeid(T) == typeid(double))
		{
			return this->doc[key].GetDouble();
		}
		if (typeid(T) == typeid(char *))
		{
			return this->doc[key].GetString();
		}
	}
	void setdefault(char * const key, const char * value)
	{
		Value v(rapidjson::kStringType);
		v.SetString(value, strlen(value), doc.GetAllocator());
		this->doc.AddMember(StringRef<char>(key), v,doc.GetAllocator());
	}
	~json();
private:
	Document doc;


};

