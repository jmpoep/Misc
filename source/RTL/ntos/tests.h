/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2026 UGN/HE
*
*  TITLE:       TESTS.H
*
*  VERSION:     2.30
*
*  DATE:        22 Jul 2026
*
*  Common header file for NTSUP test code.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

VOID Test_Sha256();
VOID Test_IsAddressValid();
VOID Test_WriteBufferToFile();
VOID Test_FindModuleNameByAddress();
VOID Test_GetLoadedModulesListEx();
VOID Test_GetSystemInfoEx();
VOID Test_HashImageSections();
VOID Test_IsObjectExists();
VOID Test_UserIsFullAdmin();
VOID Test_DuplicateUnicodeString();
VOID Test_DuplicateAnsiString();
VOID Test_QueryProcessCommandLine();
VOID Test_QueryResourceData();
VOID Test_ResolveSymbolicLink();
VOID Test_LookupImageSectionByName();
VOID Test_QueryEnvironmentVariableOffset();

VOID Tests_RunAll();

extern BOOL g_IsElevated;
