#pragma once

#define IOCTRL_BASE 0x800

#define MYIOCTRL_CODE(i) \
	CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE+i, METHOD_BUFFERED,FILE_ANY_ACCESS)

#define CTL_GetFunListSize				MYIOCTRL_CODE(0)
#define CTL_GetFunListInfo				MYIOCTRL_CODE(1)
#define CTL_SendFunListInfo				MYIOCTRL_CODE(2)

#define CTL_GetTypeListSize				MYIOCTRL_CODE(3)
#define CTL_GetTypeListInfo				MYIOCTRL_CODE(4)
#define CTL_SendTypeListInfo			MYIOCTRL_CODE(5)
#define CTL_SymbolIsSuccess				MYIOCTRL_CODE(7)

#define		Symbol_NameLength			0x50
#define		Symbol_ModuleNameLength		0x20
#define		Symbol_InfoListMax			0x20


typedef enum _EnumSymbolType
{
	Symbol_Function,
	Symbol_Type
}EnumSymbolType;



typedef	struct _SymbolFunListInfo
{
	char			Name[Symbol_NameLength];
	ULONG64			Addr;
}SymbolFunListInfo, *PSymbolFunListInfo;

typedef struct  _PakeFunListSymbol
{
	ULONG64						SymbolNumber;
	char						ModuleName[Symbol_ModuleNameLength];
	SymbolFunListInfo			SymbolInfoList[1];
}PakeFunListSymbol, *PPakeFunListSymbol;

typedef struct _SymbolGetFunction
{
	char					Name[Symbol_NameLength];
	PVOID	*				ReceiveFunction;
}SymbolGetFunction,*PSymbolGetFunction;


typedef struct _SymbolGetTypeOffset
{
	char		ParentName[Symbol_NameLength];
	char		SonName[Symbol_NameLength];
	PULONG64		Offset;
}SymbolGetTypeOffset, *PSymbolGetTypeOffset;

typedef struct _SymbolGetTypeOffsetList
{
	char					ModuleName[Symbol_ModuleNameLength];
	SymbolGetTypeOffset		InfoList[Symbol_InfoListMax];
}SymbolGetTypeOffsetList, *PSymbolGetTypeOffsetList;

typedef struct _SymbolGetFunctionInfoList
{
	char					ModuleName[Symbol_ModuleNameLength];
	SymbolGetFunction		InfoList[Symbol_InfoListMax];
}SymbolGetFunctionInfoList, *PSymbolGetFunctionInfoList;

typedef struct _InfoOfSizeList 
{
	ULONG	StructSize;
	ULONG	ListCount;
}InfoOfSizeList,*PInfoOfSizeList;
