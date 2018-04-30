/*
*	Command Line Test: C:\Windows\System32\ntdll.dll
*/


#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>
#include <Windows.h>
#include "Log.h"
#include "distorm 3.3.3\distorm.h"


DWORD RvaToOffset(IMAGE_NT_HEADERS *NT, DWORD Rva);
VOID AddFunctionToLog(BYTE *FileBuf, DWORD FuncRVA);
VOID GetInstructionString(char *Str, _DecodedInst *Instr);


int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hFile;
	DWORD FileSize = 0, nBytesRead = 0, ET_RVA = 0, j = 0, x = 0;
	BYTE *FileBuf = NULL;
	IMAGE_DOS_HEADER *pDosHeader = NULL;
	IMAGE_NT_HEADERS *pNtHeaders = NULL;
	IMAGE_EXPORT_DIRECTORY *pExportDir = NULL;
	DWORD *pFunctions = NULL, *pNames = NULL;

	// Check Command Line
	if (argc < 1) 
		return 0;
	
	// Open File For Reading
	hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE){		
		return 0;
	}

	// Allocate & Read File Into Memory
	FileSize = GetFileSize(hFile, NULL);		
	FileBuf = new BYTE [FileSize];
	if (FileBuf != NULL)
	{
		ReadFile(hFile, FileBuf, FileSize, &nBytesRead, NULL);
		CloseHandle(hFile);

		// Set PE Pointers
		pDosHeader = (IMAGE_DOS_HEADER *)FileBuf;
		pNtHeaders = (IMAGE_NT_HEADERS *)(pDosHeader->e_lfanew + (ULONG_PTR)FileBuf);

		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE  ||
			pNtHeaders->Signature != IMAGE_NT_SIGNATURE ||
			pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		{
			delete[] FileBuf;
			return 0;
		}

		// Set Export Pointers
		ET_RVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		pExportDir = (IMAGE_EXPORT_DIRECTORY *)(RvaToOffset(pNtHeaders, ET_RVA) + (ULONG_PTR)FileBuf);
		pFunctions = (DWORD *)(RvaToOffset(pNtHeaders, pExportDir->AddressOfFunctions) + (ULONG_PTR)FileBuf);
		pNames = (DWORD *)(RvaToOffset(pNtHeaders, pExportDir->AddressOfNames) + (ULONG_PTR)FileBuf);
		Log("Number of Exported Functions: #[%d]\n", pExportDir->NumberOfFunctions);
		Log("Export Base: [%d]\n\n\n", pExportDir->Base); // Starting Ordinal Index Value

		// Linear Probing the EAT.	
		for (x = 0; x < pExportDir->NumberOfFunctions; x++)
		{
			if (pFunctions[x] == 0)
				continue;

			Log("Export Address Index: [%d]\n", x + 1); // Use The Starting Ordinal Index Value
			Log("Function Virtual Address: [%X],", (DWORD*)(RvaToOffset(pNtHeaders, pFunctions[x]) + (ULONG_PTR)FileBuf));
			Log(" RVA: [%X],", pFunctions[x]);
			Log(" File Offset: [%X]\n", RvaToOffset(pNtHeaders, pFunctions[x]));

			// Start ntdll.dll @ The 8th Location For ENT.
			if (x <= 7) {
				Log("Unknown:\n"); // Place Holder For Functions Called By Ordinal.
			}
			else {
				Log("Export Name Index: [%d]\n", j);
				Log("Name Virtual Address: [%X],", (DWORD*)(RvaToOffset(pNtHeaders, pNames[j]) + (ULONG_PTR)FileBuf));
				Log(" RVA: [%X],", pNames[j]);
				Log(" File Offset: [%X]\n", RvaToOffset(pNtHeaders, pNames[j]));
				Log("%s:\n", (DWORD*)(RvaToOffset(pNtHeaders, pNames[j]) + (ULONG_PTR)FileBuf));
				j++;
			}

			// Lets Add Our Functions To The Log
			AddFunctionToLog(FileBuf, pFunctions[x]);
		}
	}
	delete[] FileBuf;
	return 0;
}


VOID AddFunctionToLog(BYTE *FileBuf, DWORD FuncRVA)
{

#define MAX_INSTRUCTIONS 100

	IMAGE_NT_HEADERS *pNtHeaders = (IMAGE_NT_HEADERS *)( (*(IMAGE_DOS_HEADER *)FileBuf).e_lfanew + (ULONG_PTR)FileBuf );
	_DecodeResult res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0;

#ifdef _M_IX86
	_DecodeType dt = Decode32Bits; // 32 bit
#define BYTE_COUNT 10              // How many bytes do you want to log?
#else ifdef _M_AMD64	
	_DecodeType dt = Decode64Bits; // 64 bit
#define BYTE_COUNT 14              // How many bytes do you want to log?
#endif

	_OffsetType offset = 0;
	res = distorm_decode( offset,	                                                  // Code Offset, This is the placement inside the function you want to start.
						  (const BYTE *)&FileBuf[ RvaToOffset(pNtHeaders, FuncRVA) ], // Code, This could be a function you want to decode.
						  50,		                                                  // Code Length, This could be described as your function length.
						  dt,				                                          // Architecture type, x86(32 bit) or x64(64 bit).
						  decodedInstructions,                                        // Decoded instruction array.
						  MAX_INSTRUCTIONS,			                                  // Max decoded instruction array size.
						  &decodedInstructionsCount	                                  // Total elements inside decoded instruction array.
	);
	if (res == DECRES_INPUTERR)
		return;

	DWORD InstrSize = 0;
	for (UINT x = 0; x < decodedInstructionsCount; x++)
	{
		if (InstrSize >= BYTE_COUNT)
			break;

		InstrSize += decodedInstructions[x].size;

		char Instr[100];
		GetInstructionString(Instr, &decodedInstructions[x]);
		Log("%s\n", Instr);
	}

	Log("\n\n\n");
}


VOID GetInstructionString(char *Str, _DecodedInst *Instr)
{
	wsprintfA(Str, "%-25s %s %s", Instr->instructionHex.p, Instr->mnemonic.p, Instr->operands.p);
	_strlwr_s(Str, 100); // string to lower case
}


DWORD RvaToOffset(IMAGE_NT_HEADERS *NT, DWORD Rva)
{
	DWORD Offset = Rva, Limit;
	IMAGE_SECTION_HEADER *Section;
	WORD i;

	Section = IMAGE_FIRST_SECTION(NT);

	if (Rva < Section->PointerToRawData)
		return Rva;

	for (i = 0; i < NT->FileHeader.NumberOfSections; i++)
	{
		if (Section[i].SizeOfRawData)
			Limit = Section[i].SizeOfRawData;
		else
			Limit = Section[i].Misc.VirtualSize;

		if (Rva >= Section[i].VirtualAddress &&	Rva < (Section[i].VirtualAddress + Limit))
		{
			if (Section[i].PointerToRawData != 0)
			{
				Offset -= Section[i].VirtualAddress;
				Offset += Section[i].PointerToRawData;
			}

			return Offset;
		}
	}

	return 0;
}

