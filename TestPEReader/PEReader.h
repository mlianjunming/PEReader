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
		dosͷ��Ϊ�˼��ݾɰ汾��dosϵͳ
	*/
	PIMAGE_DOS_HEADER m_pDosHeader;
	/*
		NTͷ�������ļ�ͷ�Ϳ�ѡͷ
		32��64�������ڿ�ѡͷ�ṹIMAGE_OPTIONAL_HEADER32(64),�ɸ���OptionalHeader.Magic��ֵ���ж�ѡ���ĸ��ṹȥ����
	*/
	PIMAGE_NT_HEADERS32 m_pNTHeader32;
	PIMAGE_NT_HEADERS64 m_pNTheader64; 
	/*
		�����������������Ϣ
		���������ڴ���ƫ��,�ߴ磬�ļ���ƫ�ƣ��ߴ磬�ֱ��Կ�ѡͷ�е�SectionAlignment��FileAlignment��ֵ����
	*/
	PIMAGE_SECTION_HEADER m_pSectionHeader; 
	/*
		IID:
		һ���Ӧһ������dll����NULL����
		Name��dll����
		OriginalFirstThunk��IAT��INT����ָ�����飬ָ��PIMAGE_IMPORT_BY_NAME
		FirstThunk��IAT��PEװ������д,��̬����û��
		*/
	PIMAGE_IMPORT_DESCRIPTOR m_pIID;
	/*
		IED:
		Base:����
		DWORD   NumberOfFunctions; // ������������
		DWORD   NumberOfNames; // ��������������
		DWORD   AddressOfFunctions;     // RVA from base of image
		DWORD   AddressOfNames;         // RVA from base of image
		DWORD   AddressOfNameOrdinals;  // RVA from base of image
	*/
	PIMAGE_EXPORT_DIRECTORY m_pIED; 
	/*
		��ԴĿ¼��
		��һ��Ŀ¼����Դ����
		�ڶ���Ŀ¼����ԴID/����
		������Ŀ¼����Դ����ҳ
	*/
	PIMAGE_RESOURCE_DIRECTORY m_pResourceDirectory;
	// ����m_pResourceDirectory�ĵ�ַ���section��ַ��TODO: ��֪���᲻���ж����Դsection�����������Ŀǰû����
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