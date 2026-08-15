/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2026
*
*  TITLE:       GLOBAL.CPP
*
*  VERSION:     1.250
*
*  DATE:        23 Jul 2026
*
*  NTOS global include file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#if !defined UNICODE
#error ANSI build is not supported
#endif

#if defined (_MSC_VER)
#if (_MSC_VER <= 1900)
#pragma warning(disable: 4214)
#pragma warning(disable: 4204)
#endif
#if (_MSC_VER >= 1900)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#if defined (_MSC_VER)
#if (_MSC_VER >= 1920)
#pragma comment(linker,"/merge:_RDATA=.rdata")
#endif
#endif

#include <Windows.h>
#pragma warning(push)
#pragma warning(disable: 4005) // macro redefinition
#include <ntstatus.h>
#pragma warning(pop)
#include "ntos.h"
#include "ntsup.h"
#include "tests.h"
