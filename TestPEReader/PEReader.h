#pragma once
#include "define.h"
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <winnt.h>
#include <string>
#include <map>
#include <time.h>
#include <vector>

#define MAX_FUNCNAME_SIZE 512
#define LINE_BUFF_LEN 256
class PEReader
{
	enum PEError
	{
		FAILED = -1,
		SUCCESS = 0,
		NOT_PE_FILE = 1
	};
	enum RESOURCE_DIRECTORY_LAYER
	{
		LAYER_TYPE=0,
		LAYER_ID,
		LAYER_LANGUAGE,
	};
	typedef struct _RESOURCE_ITEM
	{
		WORD type;
		WORD id;
		WORD language;
		RESOURCE_DIRECTORY_LAYER layer;
		PIMAGE_RESOURCE_DATA_ENTRY data;
	}RESOURCE_ITEM, *PRESOURCE_ITEM;
	typedef struct _IMPORT_FUNC
	{
		BOOL isname;
		std::string name;
	}IMPORT_FUNC;
	typedef struct _IMPORT_ITEM
	{
		std::string dllname;
		std::vector<IMPORT_FUNC> vecFunc;
	}IMPORT_ITEM;
	typedef struct _EXPORT_FUNC
	{
		DWORD rva;
		DWORD ordinal;
		std::string name;
	}EXPORT_FUNC;
	typedef struct _EXPORT_ITEM
	{
		std::string dllname;
		std::vector<EXPORT_FUNC> vecFunc;
	}EXPORT_ITEM;
public:
	PEReader();
	PEReader(const char*);
	~PEReader();
	int Reload(const char*);
	int Reload(const wchar_t*);
	int Reload(FILE* f);
	inline BOOL IsValid(){ return m_bIsPEFile; }
	std::string GetDosHeaderString();
	std::string GetNTHeaderString();
	std::string GetFileHeaderString();
	std::string GetOptHeaderString();
	std::string GetExportDataString();
	std::string GetImportDataString();
	std::string GetSectionDataString();

	void ShowResourceNode(PIMAGE_RESOURCE_DIRECTORY pIRD,PRESOURCE_ITEM pResItem);
private:
	char* m_filebuf;
	/*
		dos头：为了兼容旧版本的dos系统
	*/
	PIMAGE_DOS_HEADER m_pDosHeader;
	/*
		NT头：包含文件头和可选头
		32和64区别在于可选头结构IMAGE_OPTIONAL_HEADER32(64),可根据OptionalHeader.Magic的值来判断选用哪个结构去解析
	*/
	PIMAGE_NT_HEADERS32 m_pNTHeader32;
	PIMAGE_NT_HEADERS64 m_pNTheader64; 
	/*
		区块表：描述区块信息
		描述区块内存中偏移,尺寸，文件中偏移，尺寸，分别以可选头中的SectionAlignment和FileAlignment的值对齐
	*/
	PIMAGE_SECTION_HEADER m_pSectionHeader; 
	/*
		IID:
		一项对应一个导入dll，以NULL结束
		Name：dll名称
		OriginalFirstThunk：IAT（INT），指针数组，指向PIMAGE_IMPORT_BY_NAME
		FirstThunk：IAT由PE装载器填写,静态分析没用
		*/
	PIMAGE_IMPORT_DESCRIPTOR m_pIID;
	/*
		IED:
		Base:基数
		DWORD   NumberOfFunctions; // 导出函数数量
		DWORD   NumberOfNames; // 导出函数名数量
		DWORD   AddressOfFunctions;     // RVA from base of image
		DWORD   AddressOfNames;         // RVA from base of image
		DWORD   AddressOfNameOrdinals;  // RVA from base of image
	*/
	PIMAGE_EXPORT_DIRECTORY m_pIED; 
	/*
		资源目录：
		第一层目录：资源类型
		第二层目录：资源ID/名称
		第三层目录：资源代码页
	*/
	PIMAGE_RESOURCE_DIRECTORY m_pResourceDirectory;
	// 根据m_pResourceDirectory的地址获得section地址，TODO: 不知道会不会有多个资源section的情况，这里目前没考虑
	PIMAGE_SECTION_HEADER m_ResourceSection; 
	std::vector<RESOURCE_ITEM> m_vecRes;
	std::vector<IMPORT_ITEM> m_vecImp;
	std::vector<IMAGE_SECTION_HEADER> m_vecSections;
	EXPORT_ITEM m_Exp;
	BOOL m_bIs64File;
	BOOL m_bIsPEFile;
	void initMachineMap();
	static std::map<WORD, std::string> MachineMap;

	DWORD GetFileOffsetFromRVA(DWORD va, DWORD base);
	DWORD GetTargetAddressFromRVA(DWORD rva, DWORD base);
	PIMAGE_SECTION_HEADER GetSectionFromRVA(DWORD rva);
	void clean();
};