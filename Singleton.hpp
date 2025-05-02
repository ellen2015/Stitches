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

protected:
	static T* instance;
public:
	static T* getInstance()
	{
		if (instance)
		{
			return instance;
		}
		else
		{
			instance = new(NonPagedPoolNx) T;
			NT_ASSERT(instance != nullptr);
			return instance;
		}
	}
};

template<typename T>
__declspec(selectany) T* Singleton<T>::instance;
