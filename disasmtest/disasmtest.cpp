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
	if (argc < 1) 
		return 0;
		
	// Open PE file	
	HANDLE hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL,	OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE){		
		return 0;
	}

	DWORD FileSize = GetFileSize(hFile, NULL);

	DWORD BRW;
	BYTE *FileBuf = new BYTE [FileSize];	
	if (FileBuf)
		ReadFile(hFile, FileBuf, FileSize, &BRW, NULL);
	CloseHandle(hFile);

	IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)FileBuf;
	IMAGE_NT_HEADERS *pNtHeaders = (IMAGE_NT_HEADERS *)( (FileBuf != NULL ?	pDosHeader->e_lfanew : 0) + (ULONG_PTR)FileBuf );

	if ( !FileBuf || 
		 pDosHeader->e_magic   != IMAGE_DOS_SIGNATURE  ||
		 pNtHeaders->Signature != IMAGE_NT_SIGNATURE   ||
		 pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{		
		if (FileBuf)
			delete FileBuf;
		return 0;
	}

	
	// Walk through export dir's functions	
	DWORD ET_RVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	IMAGE_EXPORT_DIRECTORY *pExportDir = (IMAGE_EXPORT_DIRECTORY *)( RvaToOffset(pNtHeaders, ET_RVA) + (ULONG_PTR)FileBuf );
	DWORD *pFunctions = (DWORD *)( RvaToOffset(pNtHeaders, pExportDir->AddressOfFunctions) + (ULONG_PTR)FileBuf );
	DWORD *pNames     = (DWORD *)( RvaToOffset(pNtHeaders, pExportDir->AddressOfNames) + (ULONG_PTR)FileBuf);

	Log("Number of Exported Functions: #[%d]\n", pExportDir->NumberOfFunctions);
	Log("Export Base: [%d]\n\n\n", pExportDir->Base);  // Starting Ordinal Index Value
	
	// Linear Probing the EAT.
	DWORD j = 0; // Name Index
	for ( DWORD x = 0; x < pExportDir->NumberOfFunctions; x++ )
	{
		if (pFunctions[x] == 0) 
			continue;
		
		Log( "Export Address Index: [%d]\n", x + 1 );
		Log( "Function Virtual Address: [%X],", (DWORD*)(RvaToOffset(pNtHeaders, pFunctions[x]) + (ULONG_PTR)FileBuf) );
		Log( " RVA: [%X],", pFunctions[x] );
		Log( " File Offset: [%X]\n", RvaToOffset(pNtHeaders, pFunctions[x]) );		
		
		// Start ntdll.dll @ the 8th location for ENT.
		if ( x <= 7 ) {
			Log("Unknown:\n");
		} else {
			Log( "Export Name Index: [%d]\n", j);
			Log( "Name Virtual Address: [%X],", (DWORD*)( RvaToOffset(pNtHeaders, pNames[j]) + (ULONG_PTR)FileBuf ) );
			Log( " RVA: [%X],", pNames[j] );
			Log( " File Offset: [%X]\n", RvaToOffset(pNtHeaders, pNames[j]) );
			Log( "%s:\n", (DWORD*)(RvaToOffset(pNtHeaders, pNames[j]) + (ULONG_PTR)FileBuf));
			j++;
		}

		AddFunctionToLog(FileBuf, pFunctions[x]);
	}

	delete FileBuf;
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
	IMAGE_SECTION_HEADER *Img;
	WORD i;

	Img = IMAGE_FIRST_SECTION(NT);

	if (Rva < Img->PointerToRawData)
		return Rva;

	for (i = 0; i < NT->FileHeader.NumberOfSections; i++)
	{
		if (Img[i].SizeOfRawData)
			Limit = Img[i].SizeOfRawData;
		else
			Limit = Img[i].Misc.VirtualSize;

		if (Rva >= Img[i].VirtualAddress &&	Rva < (Img[i].VirtualAddress + Limit))
		{
			if (Img[i].PointerToRawData != 0)
			{
				Offset -= Img[i].VirtualAddress;
				Offset += Img[i].PointerToRawData;
			}

			return Offset;
		}
	}

	return NULL;
}

