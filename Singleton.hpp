#pragma once
#include "New.hpp"

template<typename T>
class Singleton
{
protected:
	Singleton() = default;
	~Singleton() = default;

	Singleton(const Singleton&) = delete;
	Singleton(Singleton&&) = delete;
	Singleton& operator=(const Singleton&) = delete;

private:
	static T* _Instance;
public:
	static T* getInstance()
	{
		if (_Instance)
		{
			return _Instance;
		}
		else
		{
			auto pObject = new(NonPagedPoolNx) T;
			if (!InterlockedCompareExchangePointer((PVOID*)&_Instance, pObject, nullptr))
			{
				return _Instance;
			}
			else
			{
				delete pObject;
				return _Instance;
			}
		}
	}
};

template<typename T>
__declspec(selectany) T* Singleton<T>::_Instance;
