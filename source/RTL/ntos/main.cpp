/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2026
*
*  TITLE:       NTOS.CPP
*
*  VERSION:     1.250
*
*  DATE:        23 Jul 2026
*
*  NTOS header and NTSUP RTL playground and template project.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#include "global.h"

BOOL g_IsElevated;

UINT DoTest()
{   
    ntsupIsProcessElevated(HandleToUlong(NtCurrentTeb()->ClientId.UniqueProcess), &g_IsElevated);
    Tests_RunAll();
    return 0;
}

#pragma comment(linker, "/ENTRY:main")
int main()
{
    __security_init_cookie();
    ExitProcess(DoTest());
}

