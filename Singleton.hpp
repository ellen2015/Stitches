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
			if (!InterlockedCompareExchangePointer((PVOID*)&_Instance, reinterpret_cast<PVOID>(0x1), nullptr))
			{
				auto pObject = new(NonPagedPoolNx) T;

				InterlockedCompareExchangePointer((PVOID*)&_Instance, pObject, reinterpret_cast<PVOID>(0x1));

				return _Instance;
			}
			else
			{
				return forceWait();
			}
		}
	}

	static T* forceWait()
	{
		while (((ULONG_PTR)_Instance >> 48) == 0) _mm_pause();

		return _Instance;
	}
};

template<typename T>
__declspec(selectany) T* Singleton<T>::_Instance;
