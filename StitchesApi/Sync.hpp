#pragma once 
#include "pch.h"

namespace StitchesApi
{
	class AutoHandle
	{
	public:
		AutoHandle() throw();
		AutoHandle(AutoHandle& h) throw();
		explicit AutoHandle(HANDLE h) throw();
		~AutoHandle() noexcept;

		AutoHandle& operator=(AutoHandle& h) throw();

		operator HANDLE() const throw();

		// Attach to an existing handle (takes ownership).
		void Attach(HANDLE h) throw();
		// Detach the handle from the object (releases ownership).
		HANDLE Detach() throw();

		// Close the handle.
		void Close() throw();

	public:
		HANDLE m_handle;
	};

	inline AutoHandle::AutoHandle() throw() :
		m_handle(INVALID_HANDLE_VALUE)
	{
	}

	inline AutoHandle::AutoHandle(AutoHandle& h) throw() :
		m_handle(INVALID_HANDLE_VALUE)
	{
		Attach(h.Detach());
	}

	inline AutoHandle::AutoHandle(HANDLE h) throw() :
		m_handle(h)
	{
	}

	inline AutoHandle::~AutoHandle() noexcept
	{
		if (m_handle != INVALID_HANDLE_VALUE)
		{
			Close();
		}
	}

	inline AutoHandle& AutoHandle::operator=(AutoHandle& h) throw()
	{
		if (this != &h)
		{
			if (m_handle != INVALID_HANDLE_VALUE)
			{
				Close();
			}
			Attach(h.Detach());
		}

		return(*this);
	}

	inline AutoHandle::operator HANDLE() const throw()
	{
		return(m_handle);
	}

	inline void AutoHandle::Attach(HANDLE h) throw()
	{
		m_handle = h;  // Take ownership
	}

	inline HANDLE AutoHandle::Detach() throw()
	{
		HANDLE h;

		h = m_handle;  // Release ownership
		m_handle = INVALID_HANDLE_VALUE;

		return(h);
	}

	inline void AutoHandle::Close() throw()
	{
		if (m_handle != INVALID_HANDLE_VALUE)
		{
			::CloseHandle(m_handle);
			m_handle = INVALID_HANDLE_VALUE;
		}
	}
}