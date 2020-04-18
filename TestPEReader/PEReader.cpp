#include "stdafx.h"
#include "PEReader.h"
std::map<WORD, std::string> PEReader::MachineMap = std::map<WORD, std::string>();
PEReader::PEReader()
{
	initMachineMap();
}
PEReader::PEReader(const char* filename)
{
	PEReader();
	m_filebuf = NULL;
	Reload(filename);
}

PEReader::~PEReader()
{
	free(m_filebuf);
}

void PEReader::initMachineMap()
{
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_UNKNOWN, "IMAGE_FILE_MACHINE_UNKNOWN"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_I386, "IMAGE_FILE_MACHINE_I386"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_R3000, "IMAGE_FILE_MACHINE_R3000"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_R4000, "IMAGE_FILE_MACHINE_R4000"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_R10000, "IMAGE_FILE_MACHINE_R10000"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_WCEMIPSV2, "IMAGE_FILE_MACHINE_WCEMIPSV2"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_ALPHA, "IMAGE_FILE_MACHINE_ALPHA"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_SH3, "IMAGE_FILE_MACHINE_SH3"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_SH3DSP, " IMAGE_FILE_MACHINE_SH3DSP"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_SH3E, "IMAGE_FILE_MACHINE_SH3E"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_SH4, "IMAGE_FILE_MACHINE_SH4"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_SH5, "IMAGE_FILE_MACHINE_SH5"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_ARM, "IMAGE_FILE_MACHINE_ARM"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_THUMB, "IMAGE_FILE_MACHINE_THUMB"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_ARMNT, "IMAGE_FILE_MACHINE_ARMNT"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_AM33, "IMAGE_FILE_MACHINE_AM33"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_POWERPC, "IMAGE_FILE_MACHINE_POWERPC"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_POWERPCFP, "IMAGE_FILE_MACHINE_POWERPCFP"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_IA64, "IMAGE_FILE_MACHINE_IA64"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_MIPS16, "IMAGE_FILE_MACHINE_MIPS16"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_ALPHA64, "IMAGE_FILE_MACHINE_ALPHA64"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_MIPSFPU, "IMAGE_FILE_MACHINE_MIPSFPU"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_MIPSFPU16, "IMAGE_FILE_MACHINE_MIPSFPU16"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_AXP64, "IMAGE_FILE_MACHINE_AXP64"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_TRICORE, "IMAGE_FILE_MACHINE_TRICORE"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_CEF, "IMAGE_FILE_MACHINE_CEF"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_EBC, "IMAGE_FILE_MACHINE_EBC"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_AMD64, "IMAGE_FILE_MACHINE_AMD64"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_M32R, "IMAGE_FILE_MACHINE_M32R"));
	PEReader::MachineMap.insert(std::map<WORD, std::string>::value_type(IMAGE_FILE_MACHINE_CEE, "IMAGE_FILE_MACHINE_CEE"));
}
int PEReader::ReloadBuf(char* buf)
{
	m_pebuf = buf;
	// 定位dos头
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_pebuf;
	if (m_pDosHeader->e_magic != 0x5a4d)
	{
		ERRORPRINT("get dos header magic error\n");
		return PEError::NOT_PE_FILE;
	}
	// 定位nt头（文件头+可选头）
	m_pNTHeader32 = (PIMAGE_NT_HEADERS32)(m_pebuf + m_pDosHeader->e_lfanew);
	m_pNTheader64 = (PIMAGE_NT_HEADERS64)(m_pebuf + m_pDosHeader->e_lfanew);
	if (m_pNTHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		m_bIs64File = FALSE;
		m_bIsPEFile = TRUE;
		m_pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)m_pNTHeader32 + sizeof(IMAGE_NT_HEADERS32));
		m_pIID = (PIMAGE_IMPORT_DESCRIPTOR)GetTargetAddressFromRVA(m_pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, 0);
		m_pIED = (PIMAGE_EXPORT_DIRECTORY)GetTargetAddressFromRVA(m_pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, 0);
		m_pResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)GetTargetAddressFromRVA(m_pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, 0);
		m_ResourceSection = (PIMAGE_SECTION_HEADER)GetSectionFromRVA(m_pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
	}
	else if (m_pNTHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		m_bIs64File = TRUE;
		m_bIsPEFile = TRUE;
		m_pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)m_pNTheader64 + sizeof(IMAGE_NT_HEADERS64));
		m_pIID = (PIMAGE_IMPORT_DESCRIPTOR)GetTargetAddressFromRVA(m_pNTheader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, 0);
		m_pIED = (PIMAGE_EXPORT_DIRECTORY)GetTargetAddressFromRVA(m_pNTheader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, 0);
		m_pResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)GetTargetAddressFromRVA(m_pNTheader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, 0);
		m_ResourceSection = (PIMAGE_SECTION_HEADER)GetSectionFromRVA(m_pNTheader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
	}
	else
	{
		ERRORPRINT("optional header magic beyond expectations\n");
	}

	// 获取资源信息
	m_vecRes.clear();
	PRESOURCE_ITEM pResItem = new RESOURCE_ITEM();
	ShowResourceNode(m_pResourceDirectory, pResItem);

	// 获取section信息
	for (WORD i = 0; i < m_pNTHeader32->FileHeader.NumberOfSections; i++)
	{
		DEBUGPRINT("get section:%s va:0x%08x vsize:%ld ra:0x%08x rsize:%ld\n",
			m_pSectionHeader[i].Name, m_pSectionHeader[i].VirtualAddress, m_pSectionHeader[i].Misc.VirtualSize,
			m_pSectionHeader[i].PointerToRawData, m_pSectionHeader[i].SizeOfRawData);
		IMAGE_SECTION_HEADER tmpSection = m_pSectionHeader[i];
		m_vecSections.push_back(tmpSection);
	}

	// 获取导出表
	if (m_pIED)
	{
		EXPORT_ITEM tmpExportItem;
		char *szDllName = (char*)GetTargetAddressFromRVA(m_pIED->Name, 0);
		tmpExportItem.dllname = szDllName;
		DEBUGPRINT("get IED Name:%s\n", szDllName);
		DWORD* pdwNameTableRVA = (DWORD*)GetTargetAddressFromRVA(m_pIED->AddressOfNames, 0);
		WORD* pdwOrdinalTableRVA = (WORD*)GetTargetAddressFromRVA(m_pIED->AddressOfNameOrdinals, 0);
		DWORD* pdwFuncTableRVA = (DWORD*)GetTargetAddressFromRVA(m_pIED->AddressOfFunctions, 0);
		for (DWORD i = 0; i < m_pIED->NumberOfNames; i++)
		{
			EXPORT_FUNC tmpExportFunc;
			char* szFuncName = (char*)GetTargetAddressFromRVA(pdwNameTableRVA[i], 0);
			tmpExportFunc.name = szFuncName;
			tmpExportFunc.ordinal = pdwOrdinalTableRVA[i] + m_pIED->Base;
			tmpExportFunc.rva = pdwFuncTableRVA[pdwOrdinalTableRVA[i]];
			tmpExportItem.vecFunc.push_back(tmpExportFunc);
			DEBUGPRINT("Export Func:0x%08x:(%04x)%s\n", pdwFuncTableRVA[pdwOrdinalTableRVA[i]], pdwOrdinalTableRVA[i] + m_pIED->Base, szFuncName);
		}
		m_Exp = tmpExportItem;
	}

	// 获取导入表
	if (m_bIs64File)
	{
		for (PIMAGE_IMPORT_DESCRIPTOR pIID = m_pIID; pIID->OriginalFirstThunk; pIID++)
		{
			IMPORT_ITEM tmpImportItem;
			char* name = (char*)GetTargetAddressFromRVA(pIID->Name, 0);
			tmpImportItem.dllname = name;
			DEBUGPRINT("get IID Name %s\n", name);
			// INT
			char szFuncName[MAX_FUNCNAME_SIZE];
			for (PIMAGE_THUNK_DATA64 pINT = (PIMAGE_THUNK_DATA64)GetTargetAddressFromRVA(pIID->OriginalFirstThunk, 0);
				pINT->u1.AddressOfData; pINT++)
			{
				IMPORT_FUNC tmpfunc;
				PIMAGE_IMPORT_BY_NAME pImportFunc = (PIMAGE_IMPORT_BY_NAME)GetTargetAddressFromRVA((DWORD)pINT->u1.AddressOfData, 0);
				if (IMAGE_SNAP_BY_ORDINAL64(pINT->u1.Ordinal)) // 最高位为1， 序号输入
				{
					tmpfunc.isname = FALSE;
					_snprintf_s(szFuncName, MAX_FUNCNAME_SIZE - 1, "0x%04x", IMAGE_ORDINAL64(pINT->u1.Ordinal));
					tmpfunc.name = szFuncName;
					tmpImportItem.vecFunc.push_back(tmpfunc);
					DEBUGPRINT("*funcNum:0x%04x\n", IMAGE_ORDINAL64(pINT->u1.Ordinal));
				}
				else
				{
					tmpfunc.isname = TRUE;
					_snprintf_s(szFuncName, MAX_FUNCNAME_SIZE - 1, "%s", pImportFunc->Name);
					tmpfunc.name = szFuncName;
					tmpImportItem.vecFunc.push_back(tmpfunc);
					DEBUGPRINT("0x%04x:%s\n", pImportFunc->Hint, pImportFunc->Name);
				}
			}
			m_vecImp.push_back(tmpImportItem);
		}

	}
	else
	{
		for (PIMAGE_IMPORT_DESCRIPTOR pIID = m_pIID; pIID->OriginalFirstThunk; pIID++)
		{
			IMPORT_ITEM tmpImportItem;
			char* name = (char*)GetTargetAddressFromRVA(pIID->Name, 0);
			tmpImportItem.dllname = name;
			DEBUGPRINT("get IID Name %s\n", name);
			// INT
			char szFuncName[MAX_FUNCNAME_SIZE];
			for (PIMAGE_THUNK_DATA32 pINT = (PIMAGE_THUNK_DATA32)GetTargetAddressFromRVA(pIID->OriginalFirstThunk, 0);
				pINT->u1.AddressOfData; pINT++)
			{
				IMPORT_FUNC tmpfunc;
				PIMAGE_IMPORT_BY_NAME pImportFunc = (PIMAGE_IMPORT_BY_NAME)GetTargetAddressFromRVA(pINT->u1.AddressOfData, 0);
				if (IMAGE_SNAP_BY_ORDINAL32(pINT->u1.Ordinal))
				{
					tmpfunc.isname = FALSE;
					_snprintf_s(szFuncName, MAX_FUNCNAME_SIZE - 1, "0x%04x", IMAGE_ORDINAL32(pINT->u1.Ordinal));
					tmpfunc.name = szFuncName;
					tmpImportItem.vecFunc.push_back(tmpfunc);
					DEBUGPRINT("*funcNum:0x%04x\n", IMAGE_ORDINAL32(pINT->u1.Ordinal));
				}
				else
				{
					tmpfunc.isname = TRUE;
					_snprintf_s(szFuncName, MAX_FUNCNAME_SIZE - 1, "%s", pImportFunc->Name);
					tmpfunc.name = szFuncName;
					tmpImportItem.vecFunc.push_back(tmpfunc);
					DEBUGPRINT("0x%04x:%s\n", pImportFunc->Hint, pImportFunc->Name);
				}
			}
			m_vecImp.push_back(tmpImportItem);
		}
	}
	return PEError::SUCCESS;
}
int PEReader::Reload(FILE* pFile)
{
	clean();
	long ldFileSize;
	size_t numRead = 0;
	if (!pFile)
	{
		return PEError::FAILED;
	}
	fseek(pFile, 0, SEEK_END);   ///将文件指针移动文件结尾
	ldFileSize = ftell(pFile); ///求出当前文件指针距离文件开始的字节数
	DEBUGPRINT("get file size:%ld\n", ldFileSize);
	m_filebuf = (char*)malloc(ldFileSize); // free when reload or destructor

	fseek(pFile, 0, SEEK_SET);   ///将文件指针移动文件结尾
	numRead = fread_s(m_filebuf, ldFileSize, ldFileSize, 1, pFile);
	if (numRead == 0)
	{
		ERRORPRINT("fread return 0\n");
		return PEError::FAILED;
	}
	return ReloadBuf(m_filebuf);
}
int PEReader::Reload(const char* openfile)
{
	FILE * pFile;
	errno_t err = fopen_s(&pFile, openfile, "rb");
	if (pFile == NULL)
	{
		ERRORPRINT("open file failed,err %d", err);
		clean();
		return PEError::FAILED;
	}
	int ret = Reload(pFile);
	fclose(pFile);
	return ret;
}
int PEReader::Reload(const wchar_t* openfile)
{
	FILE * pFile;
	errno_t err = _wfopen_s(&pFile, openfile, L"rb");
	if (pFile == NULL)
	{
		ERRORPRINT("open file failed,err %d", err);
		clean();
		return PEError::FAILED;
	}
	int ret = Reload(pFile);
	fclose(pFile);
	return ret;
}
std::string PEReader::GetFileHeaderString()
{
	char sztime[64] = {0};
	struct tm ttime;
	time_t tt;
	errno_t err=0;
	std::string getstr = "=============FILE HEADER============\n";
	if (!m_pNTHeader32 || !m_bIsPEFile)
		return getstr;
	char szline[LINE_BUFF_LEN] = { 0 };
	sprintf_s(szline, LINE_BUFF_LEN, "%25s:%s\n", "Machine", PEReader::MachineMap[m_pNTHeader32->FileHeader.Machine].c_str());
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%25s:0x%04x\n", "NumberOfSections", m_pNTHeader32->FileHeader.NumberOfSections);
	getstr.append(szline);
	tt = m_pNTHeader32->FileHeader.TimeDateStamp;
	err = localtime_s(&ttime, &tt);
	strftime(sztime, 64, "%Y-%m-%d %H:%M:%S", &ttime);
	sprintf_s(szline, LINE_BUFF_LEN, "%25s:0x%04x(%s)\n", "TimeDateStamp", m_pNTHeader32->FileHeader.TimeDateStamp, sztime);
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%25s:0x%04x\n", "PointerToSymbolTable", m_pNTHeader32->FileHeader.PointerToSymbolTable);
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%25s:0x%04x\n", "NumberOfSymbols", m_pNTHeader32->FileHeader.NumberOfSymbols);
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%25s:0x%04x\n", "SizeOfOptionalHeader", m_pNTHeader32->FileHeader.SizeOfOptionalHeader);
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%25s:0x%04x\n", "Characteristics", m_pNTHeader32->FileHeader.Characteristics);
	getstr.append(szline);
	return getstr;
}

std::string PEReader::GetOptHeaderString()
{
	// TODO: 输出可选头信息
	return "";
}

std::string PEReader::GetNTHeaderString()
{
	std::string headerstr = GetFileHeaderString();
	std::string optHeader = GetOptHeaderString();
	std::string retstr = headerstr;
	headerstr.append("\n").append(optHeader);
	return retstr;
}
std::string PEReader::GetDosHeaderString()
{
	std::string getstr="=============DOS Header============\n";
	if (!m_pDosHeader || !m_bIsPEFile)
		return getstr;
	char szline[LINE_BUFF_LEN] = { 0 };
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_magic]", m_pDosHeader->e_magic, "Magic DOS signature MZ(4Dh 5Ah) ");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_cblp]", m_pDosHeader->e_cblp, "Bytes on last page of file");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_cp]", m_pDosHeader->e_cp, "Pages in file");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_crlc]", m_pDosHeader->e_crlc, "Relocations");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_cparhdr]", m_pDosHeader->e_cparhdr, "Size of header in paragraphs");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_minalloc]", m_pDosHeader->e_minalloc, "Minimun extra paragraphs needs");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_maxalloc]", m_pDosHeader->e_maxalloc, "Maximun extra paragraphs needs");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_ss]", m_pDosHeader->e_ss, "intial(relative)SS value");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_sp]", m_pDosHeader->e_sp, "intial SP value");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_csum]", m_pDosHeader->e_csum, "Checksum");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_ip]", m_pDosHeader->e_ip, "intial IP value");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_cs]", m_pDosHeader->e_cs, "intial(relative)CS value");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_lfarlc]", m_pDosHeader->e_lfarlc, "File Address of relocation table");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_ovno]", m_pDosHeader->e_ovno, "Overlay number");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_oemid]", m_pDosHeader->e_oemid, "OEM identifier(for e_oeminfo)");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_oeminfo]", m_pDosHeader->e_oeminfo, "OEM information;e_oemid specific");
	getstr.append(szline);
	sprintf_s(szline, LINE_BUFF_LEN, "%-15s 0x%04x %s\n", "[e_lfanew]", m_pDosHeader->e_lfanew, "Offset to start of PE header");
	getstr.append(szline);
	return getstr;
}
std::string PEReader::GetExportDataString()
{
	std::string getstr = "=============Export Func============\n";
	char szline[LINE_BUFF_LEN] = { 0 };
	sprintf_s(szline, LINE_BUFF_LEN, "DLLNAME:%s\n", m_Exp.dllname.c_str());
	getstr.append(szline);
	for (unsigned int i = 0; i < m_Exp.vecFunc.size(); i++)
	{
		sprintf_s(szline, LINE_BUFF_LEN, "0x%08x:(%04x)%s\n", m_Exp.vecFunc[i].rva, m_Exp.vecFunc[i].ordinal, m_Exp.vecFunc[i].name.c_str());
		getstr.append(szline);
	}
	return getstr;
}
std::string PEReader::GetImportDataString()
{
	std::string getstr = "=============Import Func============\n";
	char szline[LINE_BUFF_LEN] = { 0 };
	for (unsigned int i = 0; i < m_vecImp.size(); i++)
	{
		sprintf_s(szline, LINE_BUFF_LEN, "\nmodule name:%s\n", m_vecImp[i].dllname.c_str());
		getstr.append(szline);
		for (unsigned int j = 0; j < m_vecImp[i].vecFunc.size(); j++)
		{
			sprintf_s(szline, LINE_BUFF_LEN, "%s\n", m_vecImp[i].vecFunc[j].name.c_str());
			getstr.append(szline);
		}
	}
	return getstr;
}
std::string PEReader::GetSectionDataString()
{
	std::string getstr = "============= Sections ============\n";
	char szline[LINE_BUFF_LEN] = { 0 };
	for (unsigned int i = 0; i < m_vecSections.size(); i++)
	{
		sprintf_s(szline, LINE_BUFF_LEN, "name:%s va:0x%08x vsize:%ld ra:0x%08x rsize:%ld\n", 
			m_vecSections[i].Name, m_vecSections[i].VirtualAddress, m_vecSections[i].Misc.VirtualSize,
			m_vecSections[i].PointerToRawData, m_vecSections[i].SizeOfRawData);
		getstr.append(szline);
	}
	return getstr;
}
/*
@param
	rva:RVA from imagebase
@ret
	
*/
PIMAGE_SECTION_HEADER PEReader::GetSectionFromRVA(DWORD rva)
{
	for (WORD i = 0; i < m_pNTHeader32->FileHeader.NumberOfSections; i++)
	{
		if (rva >= m_pSectionHeader[i].VirtualAddress
			&& rva < m_pSectionHeader[i].VirtualAddress + m_pSectionHeader[i].Misc.VirtualSize)
		{
			return &m_pSectionHeader[i];
		}
	}
	return NULL;
}
/*
	RVA from imagebase :    offset = RVA(a)-(SecVA-SecRA)  
	RVA from sectionbase:  offset = SecRA+ RVA(b)
*/
DWORD PEReader::GetFileOffsetFromRVA(DWORD rva,DWORD base)
{
	if (0 == base) // RVA from imagebase
	{
		PIMAGE_SECTION_HEADER pSection = GetSectionFromRVA(rva);
		if (pSection)
		{
			DWORD k = pSection->VirtualAddress - pSection->PointerToRawData;
			return rva - k;
		}
	}
	else
	{
		// RVA from sectionbase
		return rva + base;
	}
	return 0;
}

DWORD PEReader::GetTargetAddressFromRVA(DWORD rva, DWORD base)
{
	DWORD dwFileOffset = GetFileOffsetFromRVA(rva, base);
	if (dwFileOffset == 0)
		return 0;
	return (DWORD)m_pebuf + dwFileOffset;
}

void PEReader::ShowResourceNode(PIMAGE_RESOURCE_DIRECTORY pIRD, PRESOURCE_ITEM pResItem)
{
	if (!pIRD)
		return;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntryHead = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pIRD
		+ sizeof(IMAGE_RESOURCE_DIRECTORY));
	for (WORD i = 0; i < pIRD->NumberOfIdEntries + pIRD->NumberOfNamedEntries; i++)
	{
		if (pResourceEntryHead[i].NameIsString)
		{
			PIMAGE_RESOURCE_DIR_STRING_U pResString = (PIMAGE_RESOURCE_DIR_STRING_U)GetTargetAddressFromRVA(m_ResourceSection->PointerToRawData,
				pResourceEntryHead[i].Name & 0x7fff);
			std::wstring wstrName(pResString->NameString, pResString->Length);
		//	DEBUGPRINTW(L"get resource string:%s\n", wstrName.c_str());
		}
		else
		{
		//	DEBUGPRINT("get resource id:%xh\n", pResourceEntryHead[i].Id);
		}
		if (pResourceEntryHead[i].DataIsDirectory)
		{
			PIMAGE_RESOURCE_DIRECTORY pResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)GetTargetAddressFromRVA(m_ResourceSection->PointerToRawData,
				pResourceEntryHead[i].OffsetToData & 0x7fff);
			if (pIRD == m_pResourceDirectory)
			{
				// 根目录
				memset(pResItem, 0, sizeof(RESOURCE_ITEM));
				pResItem->layer = RESOURCE_DIRECTORY_LAYER::LAYER_TYPE;
				pResItem->type = pResourceEntryHead[i].Id;
			}
			if (RESOURCE_DIRECTORY_LAYER::LAYER_ID == pResItem->layer)
				pResItem->id = pResourceEntryHead[i].Id;
			pResItem->layer = RESOURCE_DIRECTORY_LAYER(pResItem->layer == RESOURCE_DIRECTORY_LAYER::LAYER_LANGUAGE ? 
															RESOURCE_DIRECTORY_LAYER::LAYER_LANGUAGE : pResItem->layer + 1);
			ShowResourceNode(pResourceDirectory, pResItem);
			pResItem->layer = RESOURCE_DIRECTORY_LAYER(pResItem->layer == RESOURCE_DIRECTORY_LAYER::LAYER_TYPE ?
				RESOURCE_DIRECTORY_LAYER::LAYER_TYPE : pResItem->layer - 1);
		}
		else
		{
			if (RESOURCE_DIRECTORY_LAYER::LAYER_LANGUAGE == pResItem->layer)
				pResItem->language = pResourceEntryHead[i].Id;
			PIMAGE_RESOURCE_DATA_ENTRY PResourceData = (PIMAGE_RESOURCE_DATA_ENTRY)GetTargetAddressFromRVA(m_ResourceSection->PointerToRawData,
				pResourceEntryHead[i].OffsetToData & 0x7fff);
			pResItem->data = PResourceData;
			m_vecRes.push_back(*pResItem);
		}
	}
}

void PEReader::clean()
{
	if (m_filebuf)
	{
		free(m_filebuf);
		m_filebuf = NULL;
	}
	m_pIED = NULL;
	m_pNTHeader32 = NULL;
	m_pNTheader64 = NULL;
	m_pResourceDirectory = NULL;
	m_pDosHeader = NULL;
	m_pSectionHeader = NULL;
	m_ResourceSection = NULL;
	m_bIs64File = FALSE;
	m_bIsPEFile = FALSE;
	m_pebuf = NULL;
	m_vecRes.clear();
	m_Exp.dllname.clear();
	m_Exp.vecFunc.clear();
	m_vecImp.clear();
	m_vecSections.clear();
}