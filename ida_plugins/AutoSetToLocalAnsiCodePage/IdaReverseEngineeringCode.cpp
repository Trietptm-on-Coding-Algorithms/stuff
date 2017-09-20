
#define BYTES_SOURCE
#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <strlist.hpp>
#include <typeinf.hpp>
#include <queue.hpp>

int g_nForceConvert=-1;

const char NullString[]="";

#define JUMPOUT(f_and_m,c) if((f_and_m)!=c) return 0

/*
int CheckCanSetName_isASCII(flags_t f)
{
//JUMPOUT(f & 0x600, 0x400);
//JUMPOUT(f & 0xF0000000, 0x50000000);
//return 1;

//相当于isASCII

return (f & MS_CLS) == FF_DATA && (f & DT_TYPE) == FF_ASCI;
}

int CheckCanSetName_isStruct(flags_t f)
{
//JUMPOUT(f & 0x600, 0x400);
//JUMPOUT(f & 0xF0000000, 0x60000000);
//return 1;

//相当于isStruct

return (f & MS_CLS) == FF_DATA && (f & DT_TYPE) == FF_STRU;
}
*/

int FmtMsgBox(int a1, const char *FmtString, const char* szTextString)
{
	//return msg(FmtString,szTextString);
	return 1;//我们就直接返回
}

//bool idaapi testf_f_has_user_name(flags_t flags, void *ud)
//{
//	return (unsigned __int16)(flags & 0xC000) == 0x4000;
//}


int CheckCanDefineTypedStringAndMsgBox(ea_t pCurItemAddr, int a2, size_t nStrLength, const char* szTextString, flags_t nFlagsParam, ea_t *pNextItemAddr1, size_t *pnRemainSize1)
{
	flags_t nFlagsParam1; // ebx@1
	ea_t pNextItemAddr; // esi@1
	flags_t nCurItemFlags; // eax@3
	flags_t fIsCode; // edi@3
	flags_t nCurItemFlags1; // ebp@3
	bool bToSetName1; // al@10
	size_t nItemSize; // eax@14
	size_t nRemainSize; // ebx@16
	flags_t nNextItemFlags; // eax@19
	int result; // eax@23
	ea_t pLastItemAddr; // edi@30
	ea_t i; // esi@30
	bool bToSetName; // [sp+30h] [bp+Ch]@3

	nFlagsParam1 = nFlagsParam;
	pNextItemAddr = pCurItemAddr;
	if ( pNextItemAddr1 )
		*pNextItemAddr1 = -1;
	bToSetName = 0;
	nCurItemFlags = get_flags_ex(pCurItemAddr, GFE_NOVALUE);
	fIsCode = nFlagsParam1 & MS_CLS;
	nCurItemFlags1 = nCurItemFlags;
	if ( fIsCode != FF_CODE || (nCurItemFlags & FF_CODE) == FF_DATA )
	{
		if ( fIsCode == FF_DATA && (nFlagsParam1 & DT_TYPE) != FF_ALIGN && (nCurItemFlags & FF_CODE) != FF_CODE )
		{
			bToSetName = 1;
			if ( isASCII(nCurItemFlags) )
			{
				bToSetName1 = isASCII(nFlagsParam1);
			}
			else
			{
				if ( !isStruct(nCurItemFlags1) )
					goto LABEL_14;
				bToSetName1 = isStruct(nFlagsParam1);
			}
			bToSetName = bToSetName1;
			if ( bToSetName1 )
				goto LABEL_14;
		}
		nRemainSize = nStrLength;
		goto LABEL_18;
	}
	bToSetName = 1;
LABEL_14:
	nItemSize = (size_t)(get_item_end(pNextItemAddr) - pNextItemAddr);
	if ( nItemSize > nStrLength )
		nItemSize = nStrLength;
	pNextItemAddr += nItemSize;
	nRemainSize = nStrLength - nItemSize;
LABEL_18:
	if ( !nRemainSize )
		return 1;
	nNextItemFlags = get_flags_ex(pNextItemAddr, GFE_NOVALUE);
	if ( (fIsCode == FF_CODE || (nNextItemFlags & 0xC000) != 0x4000)
		&& !((nNextItemFlags >> 10) & 1)
		&& (unsigned __int8)can_define_item(pNextItemAddr, nRemainSize, 0) )
	{
		return 1;
	}
	result = g_nForceConvert;
	if ( g_nForceConvert == -1 )
		result = FmtMsgBox(1, "%s", szTextString);
	if ( result == 1 )
	{
		QueueDel(Q_final, pNextItemAddr);
		if ( pNextItemAddr1 )
		{
			*pNextItemAddr1 = pNextItemAddr;
			*pnRemainSize1 = nRemainSize;
			return 1;
		}
		do_unknown_range(pNextItemAddr, nRemainSize, DOUNK_DELNAMES);
		if ( bToSetName )
			set_name(pNextItemAddr, NullString, SN_CHECK);
		pLastItemAddr = pNextItemAddr + nRemainSize;
		for ( i = nextthat(pNextItemAddr, pNextItemAddr + nRemainSize, f_has_user_name, 0);
			i != BADADDR; 
			i = nextthat(i,pLastItemAddr, f_has_user_name, 0) 
			)
		{
			set_name(i, NullString, SN_CHECK);
		}
		return 1;
	}
	return result;
}