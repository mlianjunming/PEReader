// main.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <stdio.h>
#include "define.h"
#include "PEReader.h"

int _tmain(int argc, _TCHAR* argv[])
{
	WIN32_FIND_DATA FindFileData;
	size_t length_of_arg;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD dwError = 0;
	if (argc != 2)
	{
		ERRORPRINTW(TEXT("\nUsage: %s <directory name>\n"), argv[0]);
		return (-1);
	}
	length_of_arg = wcslen(argv[1]);
	if (length_of_arg > (MAX_PATH - 3))
	{
		ERRORPRINTW(TEXT("\nDirectory path is too long.\n"));
		return (-1);
	}
	hFind = FindFirstFile(argv[1], &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		ERRORPRINT("FindFirstFile failed (%d)\n", GetLastError());
		return -1;
	}

	std::wstring checkpath = argv[1];
	if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		// 路径
		std::wstring findpath = checkpath;
		findpath.append(TEXT("\\*"));
		hFind = FindFirstFile(findpath.c_str(), &FindFileData);
		if (hFind == INVALID_HANDLE_VALUE)
		{
			ERRORPRINT("FindFirstFile failed (%d)\n", GetLastError());
			return -1;
		}
	}
	else
	{
		// 文件
		size_t flapos = checkpath.find_last_of(L"\\");
		checkpath = checkpath.substr(0, flapos);
	}

	do
	{
		if (!wcscmp(FindFileData.cFileName, L".") || !wcscmp(FindFileData.cFileName, L".."))
			continue;
		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			WARNPRINTW(TEXT("[pass check] %s is dir.\n"), FindFileData.cFileName);
		}
		else
		{
			std::wstring absolutePath = checkpath;
			absolutePath.append(L"\\").append(FindFileData.cFileName);
			PEReader peReader;
			peReader.Reload(absolutePath.c_str());
			if (peReader.IsValid())
			{
				std::string str = peReader.GetDosHeaderString();
				printf("%s\n", str.c_str());
				str = peReader.GetNTHeaderString();
				printf("%s\n", str.c_str());
				str = peReader.GetImportDataString();
				printf("%s\n", str.c_str());
				str = peReader.GetExportDataString();
				printf("%s\n", str.c_str());
				str = peReader.GetSectionDataString();
				printf("%s\n", str.c_str());
			}
			else
			{
				WARNPRINTW(TEXT("[pass check] %s is not pe file.\n"), FindFileData.cFileName);
			}
		}
	} while (FindNextFile(hFind, &FindFileData) != 0);
	FindClose(hFind);
	return 0;
}

