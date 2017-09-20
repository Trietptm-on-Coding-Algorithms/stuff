/*
*  This is a sample plugin module
*
*  It can be compiled by any of the supported compilers:
*
*      - Borland C++, CBuilder, free C++
*      - Visual C++
*      - GCC
*
*/

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

#ifdef __NT__
#include <Windows.h>
#include <tchar.h>
#else
//���Լ��������ƽ̨��ͷ�ļ�
#endif


//Mlang
//Officeʹ�õ���Mlang�Ľӿ�
#ifdef __NT__
#define _FUNC_STATIC_BAK_ FUNC_STATIC
#undef FUNC_STATIC
#include <comdef.h>
#include <comdefsp.h>
#include <Mlang.h>
#define FUNC_STATIC _FUNC_STATIC_BAK_
#undef _FUNC_STATIC_BAK_

_COM_SMARTPTR_TYPEDEF(IMultiLanguage, __uuidof(IMultiLanguage));
_COM_SMARTPTR_TYPEDEF(IMultiLanguage2, __uuidof(IMultiLanguage2));

#include <atlbase.h>
#endif

//ICU
#include "unicode/utypes.h"
#include "unicode/ucsdet.h"
#include "IdaReverseEngineeringCode.h"

////enca
////enca��Mlangʶ��������һ��
//#include "internal.h"

////libchardet
////libchardet̫����,����Ĳο��Բ���
//#include <chardet.h>

//����Mlang+ICU�����ܻ���


BOOL SystemPlatformUnicodeIsUTF16LE()
{ 
	//������֪windows�µ�PE�ļ���UNICODE������UTF-16С�˸�ʽ������ƽ̨��������ʽ��ʱ������
	return inf.filetype==f_PE;//||inf.filetype==xxx||...;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//���漸��������������Notepad2-mod,��Ŀ��ַhttps://xhmikosr.github.io/notepad2-mod/
//IsTextUnicode��ʵ�ִ���ο�WRK,��ntdll���������,���������֧�ֿ�ƽ̨��
const BOOL bSkipUnicodeDetection=FALSE;
BOOL IsUnicode(const char* pBuffer,int cb,LPBOOL lpbBOM,LPBOOL lpbReverse)
{
	int i = 0xFFFF;

	BOOL bIsTextUnicode;

	BOOL bHasBOM;
	BOOL bHasRBOM;

	if (!pBuffer || cb < 2)
		return FALSE;

	if (!bSkipUnicodeDetection)
		bIsTextUnicode = IsTextUnicode(pBuffer,cb,&i);
	else
		bIsTextUnicode = FALSE;

	bHasBOM  = (*((UNALIGNED PWCHAR)pBuffer) == 0xFEFF);
	bHasRBOM = (*((UNALIGNED PWCHAR)pBuffer) == 0xFFFE);

	if (i == 0xFFFF) // i doesn't seem to have been modified ...
		i = 0;

	if (bIsTextUnicode || bHasBOM || bHasRBOM ||
		((i & (IS_TEXT_UNICODE_UNICODE_MASK | IS_TEXT_UNICODE_REVERSE_MASK)) &&
		!((i & IS_TEXT_UNICODE_UNICODE_MASK) && (i & IS_TEXT_UNICODE_REVERSE_MASK)) &&
		!(i & IS_TEXT_UNICODE_ODD_LENGTH) &&
		!(i & IS_TEXT_UNICODE_ILLEGAL_CHARS && !(i & IS_TEXT_UNICODE_REVERSE_SIGNATURE)) &&
		!((i & IS_TEXT_UNICODE_REVERSE_MASK) == IS_TEXT_UNICODE_REVERSE_STATISTICS))) {

			if (lpbBOM)
				*lpbBOM = (bHasBOM || bHasRBOM ||
				(i & (IS_TEXT_UNICODE_SIGNATURE | IS_TEXT_UNICODE_REVERSE_SIGNATURE)))
				? TRUE : FALSE;

			if (lpbReverse)
				*lpbReverse = (bHasRBOM || (i & IS_TEXT_UNICODE_REVERSE_MASK)) ? TRUE : FALSE;

			return TRUE;
	}

	else

		return FALSE;
}

BOOL IsUTF8(const char* pTest,int nLength)
{
	static int byte_class_table[256] = {
		/*       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  */
		/* 00 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		/* 10 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		/* 20 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		/* 30 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		/* 40 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		/* 50 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		/* 60 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		/* 70 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		/* 80 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		/* 90 */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		/* A0 */ 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		/* B0 */ 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		/* C0 */ 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
		/* D0 */ 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
		/* E0 */ 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 7,
		/* F0 */ 9,10,10,10,11, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4
		/*       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  */ };

	/* state table */
	typedef enum {
		kSTART = 0,kA,kB,kC,kD,kE,kF,kG,kERROR,kNumOfStates } utf8_state;

		static utf8_state state_table[] = {
			/*                            kSTART, kA,     kB,     kC,     kD,     kE,     kF,     kG,     kERROR */
			/* 0x00-0x7F: 0            */ kSTART, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR,
			/* 0x80-0x8F: 1            */ kERROR, kSTART, kA,     kERROR, kA,     kB,     kERROR, kB,     kERROR,
			/* 0x90-0x9f: 2            */ kERROR, kSTART, kA,     kERROR, kA,     kB,     kB,     kERROR, kERROR,
			/* 0xa0-0xbf: 3            */ kERROR, kSTART, kA,     kA,     kERROR, kB,     kB,     kERROR, kERROR,
			/* 0xc0-0xc1, 0xf5-0xff: 4 */ kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR,
			/* 0xc2-0xdf: 5            */ kA,     kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR,
			/* 0xe0: 6                 */ kC,     kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR,
			/* 0xe1-0xec, 0xee-0xef: 7 */ kB,     kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR,
			/* 0xed: 8                 */ kD,     kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR,
			/* 0xf0: 9                 */ kF,     kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR,
			/* 0xf1-0xf3: 10           */ kE,     kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR,
			/* 0xf4: 11                */ kG,     kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR, kERROR };

#define BYTE_CLASS(b) (byte_class_table[(unsigned char)b])
#define NEXT_STATE(b,cur) (state_table[(BYTE_CLASS(b) * kNumOfStates) + (cur)])

			utf8_state current = kSTART;
			int i;

			const char* pt = pTest;
			int len = nLength;

			for(i = 0; i < len ; i++, pt++) {

				current = NEXT_STATE(*pt,current);
				if (kERROR == current)
					break;
			}

			return (current == kSTART) ? TRUE : FALSE;
}


BOOL IsUTF7(const char* pTest,int nLength)
{
	int i;
	const char *pt = pTest;

	for (i = 0; i < nLength; i++) {
		if (*pt & 0x80 || !*pt)
			return FALSE;
		pt++;
	}

	return TRUE;
}


#define IsUTF8Signature(p) \
	((*(p+0) == '\xEF' && *(p+1) == '\xBB' && *(p+2) == '\xBF'))


#define UTF8StringStart(p) \
	(IsUTF8Signature(p)) ? (p+3) : (p)


/* byte length of UTF-8 sequence based on value of first byte.
for UTF-16 (21-bit space), max. code length is 4, so we only need to look
at 4 upper bits.
*/
static const INT utf8_lengths[16]=
{
	1,1,1,1,1,1,1,1,        /* 0000 to 0111 : 1 byte (plain ASCII) */
	0,0,0,0,                /* 1000 to 1011 : not valid */
	2,2,                    /* 1100, 1101 : 2 bytes */
	3,                      /* 1110 : 3 bytes */
	4                       /* 1111 :4 bytes */
};

/*++
Function :
UTF8_mbslen_bytes [INTERNAL]

Calculates the byte size of a NULL-terminated UTF-8 string.

Parameters :
char *utf8_string : string to examine

Return value :
size (in bytes) of a NULL-terminated UTF-8 string.
-1 if invalid NULL-terminated UTF-8 string
--*/
static INT UTF8_mbslen_bytes(LPCSTR utf8_string)
{
	INT length=0;
	INT code_size;
	BYTE byte;

	while(*utf8_string)
	{
		byte=(BYTE)*utf8_string;

		if( (byte <= 0xF7) && (0 != (code_size = utf8_lengths[ byte >> 4 ])))
		{
			length+=code_size;
			utf8_string+=code_size;
		}
		else
		{
			/* we got an invalid byte value but need to count it,
			it will be later ignored during the string conversion */
			//WARN("invalid first byte value 0x%02X in UTF-8 sequence!\n",byte);
			length++;
			utf8_string++;
		}
	}
	length++; /* include NULL terminator */
	return length;
}

/*++
Function :
UTF8_mbslen [INTERNAL]

Calculates the character size of a NULL-terminated UTF-8 string.

Parameters :
char *utf8_string : string to examine
int byte_length : byte size of string

Return value :
size (in characters) of a UTF-8 string.
-1 if invalid UTF-8 string
--*/
static INT UTF8_mbslen(LPCSTR source, INT byte_length)
{
	INT wchar_length=0;
	INT code_size;
	BYTE byte;

	while(byte_length > 0)
	{
		byte=(BYTE)*source;

		/* UTF-16 can't encode 5-byte and 6-byte sequences, so maximum value
		for first byte is 11110111. Use lookup table to determine sequence
		length based on upper 4 bits of first byte */
		if ((byte <= 0xF7) && (0 != (code_size=utf8_lengths[ byte >> 4])))
		{
			/* 1 sequence == 1 character */
			wchar_length++;

			if(code_size==4)
				wchar_length++;

			source+=code_size;        /* increment pointer */
			byte_length-=code_size;   /* decrement counter*/
		}
		else
		{
			/*
			unlike UTF8_mbslen_bytes, we ignore the invalid characters.
			we only report the number of valid characters we have encountered
			to match the Windows behavior.
			*/
			//WARN("invalid byte 0x%02X in UTF-8 sequence, skipping it!\n",
			//     byte);
			source++;
			byte_length--;
		}
	}
	return wchar_length;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

UINT GetSystemPlatformAnsiCodePage(void)
{
#ifdef __NT__
	return GetACP();
#else
	//���Լ�ʵ�����ƽ̨��ȡACP�Ĵ���,����ʹ��libiconv�ȿ�Դ���еķ���,�����о�̫����,������
	_ASSERT(FALSE);
	return 0;
#endif
}


//--------------------------------------------------------------------------
// Example of a user-defined IDC function in C++

#if 0
static const char myfunc5_args[] = { VT_LONG, VT_STR, 0 };
static error_t idaapi myfunc5(idc_value_t *argv, idc_value_t *res)
{
	msg("myfunc is called with arg0=%x and arg1=%s\n", argv[0].num, argv[1].str);
	res->num = 5;     // let's return 5
	return eOk;
}
#endif

struct tagDetectEncodingItem 
{
	qstring strEncName;
	INT nConfidence;
public:
	static int __cdecl compare(const void *item1_, const void *item2_)
	{
		const tagDetectEncodingItem* item1=(const tagDetectEncodingItem*)item1_;
		const tagDetectEncodingItem* item2=(const tagDetectEncodingItem*)item2_;
		return item1->nConfidence-item2->nConfidence;
	}
};

BOOL TryToRerecognizeStringItem(size_t i,string_info_t si,string_info_t& si_last_modified,
	BOOL bTryToRerecognizeUnicodeString,UINT uiLocalAnsiCodePage,BOOL bSystemPlatformUnicodeIsUTF16LE,
	IMultiLanguage2Ptr& spMultiLanguage2,IStreamPtr& spIStream,
	UCharsetDetector* csd)
{
	//ATLTRACE("ea=0x%I64p len=%d\r\n",(uint64)si.ea,si.length);

	if(!isLoaded(si.ea))
	{
		_ASSERT(FALSE);
		return FALSE;
	}

	//����Ƿ���ڲ����ַ����б��е��ַ������ݼ�©��֮��
	if (i!=-1)
	{
		string_info_t si_end;
		if (i>0)
		{
			bool bRet=get_strlist_item(i-1,&si_end);
			_ASSERT(bRet);
		}
		else
		{
			si_end.ea=inf.minEA-1;
			si_end.length=0;
			si_end.type=ASCSTR_C;
		}
		ea_t minea=si_end.ea+1;
		ea_t PrevItemAddr=prevthat(si.ea,minea,f_isASCII,0);//�����ø��ϸ����Ը�Ϊf_isData
		while (PrevItemAddr!=BADADDR)
		{
			char szTextBuf[1024];
			size_t inputLength=__min((size_t)(si.ea-PrevItemAddr)+si.length,sizeof(szTextBuf));
			bool bRet=get_many_bytes(PrevItemAddr,szTextBuf,inputLength);
			_ASSERT(bRet);
			if (inputLength+4<=sizeof(szTextBuf))
			{
				szTextBuf[inputLength+0]=0;
				szTextBuf[inputLength+1]=0;
				szTextBuf[inputLength+2]=0;
				szTextBuf[inputLength+3]=0;
				//inputLength+=4;
			}

			size_t guess_min_len=0;
			while (szTextBuf[guess_min_len])//��ȡ����һ��'\0'���ַ�����ֹ����Ϊֹ
			{
				guess_min_len++;
			}
			if (guess_min_len>0)//ʹ��f_isASCIIʱ,���Ӧ���Ǳ�Ȼ��,���ң�ANSI����Unicodeʱǰ��Ϊ��Ӣ��ʱ�����ڵ�����С�ַ�������,ʹ��f_isData�Ͳ�һ����
			{
				inputLength=guess_min_len+1;

				int str_type=ASCSTR_C;

				BOOL bBOM=FALSE;
				BOOL bReverse = FALSE;
				if (IsUnicode(szTextBuf,inputLength/2*2,&bBOM,&bReverse))
				{
					if (
						(!bReverse && bSystemPlatformUnicodeIsUTF16LE)//Unicode������ΪС��UTF16�ҵ�ǰ�ַ���ΪС��Unicodeʱ
						||(bReverse && !bSystemPlatformUnicodeIsUTF16LE)//Unicode������Ϊ���UTF16�ҵ�ǰ�ַ���Ϊ���Unicodeʱ
						)
					{
						str_type=ASCSTR_UNICODE;
					}
				}

				string_info_t si_not_in_strlist;
				si_not_in_strlist.ea=PrevItemAddr;
				si_not_in_strlist.length=get_max_ascii_length(PrevItemAddr,str_type,ALOPT_IGNHEADS|ALOPT_IGNPRINT);
				si_not_in_strlist.type=ASCSTR_C;//���Ϊ����δʶ���C-style ASCII string���Դ����ٴ�ʶ��
				BOOL bResult=TryToRerecognizeStringItem(-1,si_not_in_strlist,si_last_modified,
					bTryToRerecognizeUnicodeString,uiLocalAnsiCodePage,bSystemPlatformUnicodeIsUTF16LE,
					spMultiLanguage2,spIStream,
					csd);
			}
			else
			{
				_ASSERT(FALSE);
			}

			PrevItemAddr=prevthat(PrevItemAddr,minea,f_isASCII,0);
		}
	}

	//if (si.ea==0x00469F4F)
	//{
	//	_ASSERT(FALSE);
	//	//continue;
	//}


	//�������һ���޸Ĺ����ַ����ڲ�����������Ѿ�ʧЧ���ַ�������
	if (si.ea>si_last_modified.ea && si.ea<si_last_modified.ea+si_last_modified.length)
	{
		return FALSE;
	}

	if (si.type==ASCSTR_C||si.type==ASCSTR_UNICODE)
	{
		BOOL bIsXRefed=FALSE;
		//int nXRefCount=0;
		xrefblk_t xb;
		for ( bool ok=xb.first_to(si.ea, XREF_ALL); ok; ok=xb.next_to() )
		{
			// xb.from - contains the referencing address
			//nXRefCount++;

			bIsXRefed=TRUE;
			break;
		}
		if (!bIsXRefed)//ȡ����δ���õ�ANSI��Unicode�ַ����Ķ���,��Щ���п�������Ϊ������Ĭ�ϴ���ҳ��������ʶ�������
		{
			flags_t ftItemFlags=get_flags_ex(si.ea,GFE_NOVALUE);
			_ASSERT(!isCode(ftItemFlags));

			//bRet=can_define_item(si.ea,si.length,0);
			//QueueDel(Q_final, si.ea);
			bool bRet=do_unknown(si.ea, DOUNK_EXPAND);
			//bRet=set_name(si.ea, "", SN_CHECK);
			return FALSE;
		}
	}

	//if (si.type>ASCSTR_C)//Ŀǰֻ�ٶ�IDAʶ��ΪANSI���ַ���
	//{
	//	continue;
	//}

	if (si.type!=ASCSTR_C)
	{
		if ((bTryToRerecognizeUnicodeString && si.type!=ASCSTR_UNICODE) || !bTryToRerecognizeUnicodeString)
		{
			return FALSE;
		}
	}

	char szTextBuf[1024];
	size_t inputLength=__min(si.length,sizeof(szTextBuf));
	bool bRet=get_many_bytes(si.ea,szTextBuf,inputLength);
	_ASSERT(bRet);
	if (inputLength+4<=sizeof(szTextBuf))
	{
		szTextBuf[inputLength+0]=0;
		szTextBuf[inputLength+1]=0;
		szTextBuf[inputLength+2]=0;
		szTextBuf[inputLength+3]=0;
		//inputLength+=4;
	}

	//char szRamBuf[1024];
	//netnode_supstr(si.ea,,,,stag);
	//netnode node=si.ea;
	//for(nodeidx_t alt=node.sup1st(stag);alt!=node.suplast(stag);alt=node.supnxt(alt,stag))
	//{
	// node.supstr(alt,szRamBuf,sizeof(szRamBuf),stag);
	//}

	//WCHAR* szTextBufW=(WCHAR*)szTextBuf;
	//if (szTextBufW[0]==L'��' && szTextBufW[1]==L'��')
	//{
	//	//_ASSERT(FALSE);
	//}

	//set_name//get_item_end//get_flags_ex//get_max_ascii_length//can_define_item//make_ascii_string

	qvector<tagDetectEncodingItem> DetectEncodingItemArray;

	BOOL bFindTrustedDetectEncodingItem=FALSE;
	BOOL bBOM=FALSE;
	BOOL bReverse = FALSE;
	if (IsUnicode(szTextBuf,inputLength/2*2,&bBOM,&bReverse))//inputLength/2*2��ʾ����ȡż��ֵ,Releaseʱ������Ӧ�û��Զ���λ�Ʋ�����ȡż��
	{
		if (
			(!bReverse && bSystemPlatformUnicodeIsUTF16LE)//Unicode������ΪС��UTF16�ҵ�ǰ�ַ���ΪС��Unicodeʱ
			||(bReverse && !bSystemPlatformUnicodeIsUTF16LE)//Unicode������Ϊ���UTF16�ҵ�ǰ�ַ���Ϊ���Unicodeʱ
			)
		{
			if (si.type==ASCSTR_UNICODE)//�ų����Ѿ�����ȷ����Ŀ
			{
				return FALSE;
			}

			//����netnode�Ĵ�С
#ifdef _DEBUG
			asize_t szItemOld=get_item_size(si.ea);
			wchar16_t szTextBufW[1024*8];
			szTextBufW[0]=0;
			bool bRet=get_many_bytes(si.ea,szTextBufW,sizeof(szTextBufW));
			size_t szUnicodeStringLengthSTD=qstrlen(szTextBufW);
#endif
			size_t szUnicodeStringLengthIDA=get_max_ascii_length(si.ea,ASCSTR_UNICODE,ALOPT_IGNHEADS|ALOPT_IGNPRINT);
#ifdef _DEBUG
			_ASSERT((szUnicodeStringLengthSTD+1)*sizeof(wchar16_t)==szUnicodeStringLengthIDA);//�������,Ӧ�÷�������ִ��
#endif

			int nCanDefineItem=CheckCanDefineTypedStringAndMsgBox(si.ea,0,szUnicodeStringLengthIDA,"Directly convert to string?",0x50000400,NULL,NULL);
			_ASSERT(nCanDefineItem);
			bRet=make_ascii_string(si.ea,0,ASCSTR_UNICODE);
			//bRet=make_ascii_string(si.ea,(szUnicodeStringLengthSTD+1)*sizeof(wchar16_t),ASCSTR_UNICODE);
			if (!bRet)
			{
				//do_unknown_range(si.ea,szUnicodeStringLengthIDA,DOUNK_DELNAMES);
				//bRet=make_ascii_string(si.ea,szUnicodeStringLengthIDA,ASCSTR_UNICODE);
				_ASSERT(bRet);
			}

			//����si_last_modified
			si_last_modified=si;
			si_last_modified.length=szUnicodeStringLengthIDA;
			return TRUE;
		}

		tagDetectEncodingItem DetectEncodingItem;
		DetectEncodingItem.strEncName=!bReverse?"UTF-16LE":"UTF-16BE";
		DetectEncodingItem.nConfidence=100;
		DetectEncodingItemArray.push_back(DetectEncodingItem);

		if (!bFindTrustedDetectEncodingItem && DetectEncodingItem.nConfidence>40)
		{
			bFindTrustedDetectEncodingItem=TRUE;
		}
	}
	else if (IsUTF8(szTextBuf,inputLength) && 
		(UTF8_mbslen_bytes(UTF8StringStart(szTextBuf)) - 1
		!=UTF8_mbslen(UTF8StringStart(szTextBuf),IsUTF8Signature(szTextBuf) ? inputLength-3 : inputLength))
		)
	{
		tagDetectEncodingItem DetectEncodingItem;
		DetectEncodingItem.strEncName="UTF-8";
		DetectEncodingItem.nConfidence=100;
		DetectEncodingItemArray.push_back(DetectEncodingItem);

		if (!bFindTrustedDetectEncodingItem && DetectEncodingItem.nConfidence>40)
		{
			bFindTrustedDetectEncodingItem=TRUE;
		}
	}
	if (!bFindTrustedDetectEncodingItem)
	{
#ifdef __NT__
		LARGE_INTEGER dlibMove ={0,0};
		spIStream->Seek(dlibMove, STREAM_SEEK_SET, NULL);
		ULONG cbWritten = 0;
		spIStream->Write(szTextBuf, inputLength, &cbWritten);
		ULARGE_INTEGER libNewSize={inputLength,0};
		spIStream->SetSize(libNewSize);//����Ϊ�ı�����ʵ�ʴ�С
		//spIStream->Seek(dlibMove, STREAM_SEEK_SET, NULL);//û�б�Ҫ����,DetectCodepageInIStream�ڲ����Զ���ͷ��ʼȡ����

		//����ǵ����������IMultiLanguage2�ӿڵ�һ������DetectCodepageInIStream
		DetectEncodingInfo info[32];
		INT nScores = _countof(info);
		HRESULT hr = spMultiLanguage2->DetectCodepageInIStream(MLDETECTCP_DBCS | MLDETECTCP_HTML, 0, spIStream, info, &nScores);
		if (SUCCEEDED(hr))//������S_OK,S_FALSE
		{
			int nMaxConfidence;
			int iIndexOfMaxConfidence=-1;

			for (int i = 0; i < nScores; i++)
			{
				if(i==0)
				{
					nMaxConfidence=info[i].nConfidence;
					iIndexOfMaxConfidence=i;
				}
				else
				{
					if (info[i].nConfidence>nMaxConfidence)
					{
						nMaxConfidence=info[i].nConfidence;
						iIndexOfMaxConfidence=i;
					}
				}
			}

			if (iIndexOfMaxConfidence>-1)
			{
				if(info[iIndexOfMaxConfidence].nCodePage!=uiLocalAnsiCodePage && info[iIndexOfMaxConfidence].nCodePage!=20127)
					//��ΪASCSTR_CĬ�ϵı������ACP,���Բ����ظ�����;20127Ϊus-ascii,һ��Ĵ���ҳ���Ǽ���us-ascii������Ҳ��Ҫ�ų�
				{
#ifdef _DEBUG
					CPINFOEXA CPInfoEx;
					GetCPInfoExA(info[iIndexOfMaxConfidence].nCodePage,0,&CPInfoEx);
					ATLTRACE("MLang result:0x%I64p %.*s ->%u,%s",(uint64)si.ea,(size_t)si.length,szTextBuf,CPInfoEx.CodePage,CPInfoEx.CodePageName);
#endif
					tagDetectEncodingItem DetectEncodingItem;
					DetectEncodingItem.strEncName.sprnt("CP%u",info[iIndexOfMaxConfidence].nCodePage);
					//MLang��DetectEncodingInfo::nConfidence����ܳ���100,������100*info[iIndexOfMaxConfidence].nDocPercent���׼ȷ��
					DetectEncodingItem.nConfidence=info[iIndexOfMaxConfidence].nConfidence;
					DetectEncodingItemArray.push_back(DetectEncodingItem);
					if (!bFindTrustedDetectEncodingItem && DetectEncodingItem.nConfidence>50)
					{
						bFindTrustedDetectEncodingItem=TRUE;
					}
				}
			}



		}
#endif//__NT__
		if (FAILED(hr)||!bFindTrustedDetectEncodingItem)
		{
			//������������ʶ������

			int nMaxConfidence;
			int iIndexOfMaxConfidence=-1;

			nMaxConfidence=0;

			//ICU
			UErrorCode status;
			int32_t match, matchCount = 0;
			ucsdet_setText(csd, szTextBuf, inputLength, &status);

			const UCharsetMatch **csm = ucsdet_detectAll(csd, &matchCount, &status);

			ATLTRACE("---------------------------------ICU BEGIN---------------------------------------\r\n");
			for(match = 0; match < matchCount; match += 1) 
			{
				const char *name = ucsdet_getName(csm[match], &status);
				const char *lang = ucsdet_getLanguage(csm[match], &status);
				int32_t confidence = ucsdet_getConfidence(csm[match], &status);

				if (lang == NULL || strlen(lang) == 0) {
					lang = "**";
				}

				ATLTRACE("%s (%s) %d\n", name, lang, confidence);

				if (match==0)
				{
					nMaxConfidence=confidence;
					iIndexOfMaxConfidence=match;
				}
				else
				{
					if (confidence>nMaxConfidence)
					{
						nMaxConfidence=confidence;
						iIndexOfMaxConfidence=match;
					}
				}
			}
			ATLTRACE("---------------------------------ICU END---------------------------------------\r\n");

			//*  Pure 7 bit ASCII data, for example, is compatible with a
			//*  great many charsets, most of which will appear as possible matches
			//*  with a confidence of 10.
			if (nMaxConfidence<=10)
			{
				return FALSE;
			}
			if (iIndexOfMaxConfidence>-1)
			{
				const char *name = ucsdet_getName(csm[iIndexOfMaxConfidence], &status);
				const char *lang = ucsdet_getLanguage(csm[iIndexOfMaxConfidence], &status);
				int32_t confidence = ucsdet_getConfidence(csm[iIndexOfMaxConfidence], &status);

				//����ǰ���Ѿ������ų���
				/*
				if (lang == NULL || strlen(lang) == 0) {
				lang = "**";
				}

				if (uiLocalAnsiCodePage==936 && !qstrcmp(name,"GB18030"))//ͬMLang������ACP��ԭ��
				{
				continue;
				}

				if (!qstrcmp(name,"ISO-8859-1")||!qstrcmp(name,"windows-1252"))//ͬMLang������20127��ԭ��
				{
				continue;
				}

				if (!qstrcmp(name,"UTF-8"))//ǰ���Ѿ��ж���UTF-8,�����ж�ΪUTF-8,˵���Ǵ�ASCII�ַ���
				{
				continue;
				}
				*/

				ATLTRACE("ICU result:0x%I64p %.*s ->%s(%s) %d\n",(uint64)si.ea,(size_t)si.length,szTextBuf, name, lang, confidence);

				tagDetectEncodingItem DetectEncodingItem;
				DetectEncodingItem.strEncName=name;
				DetectEncodingItem.nConfidence=confidence;
				DetectEncodingItemArray.push_back(DetectEncodingItem);
				if (!bFindTrustedDetectEncodingItem && DetectEncodingItem.nConfidence>10)
				{
					bFindTrustedDetectEncodingItem=TRUE;
				}
			}
		}
	}

	//�����޸�ָ���ַ�����ı�������
	if (DetectEncodingItemArray.size()>0 && bFindTrustedDetectEncodingItem)
	{
		if (DetectEncodingItemArray.size()>1)
		{
			qsort(DetectEncodingItemArray.begin(),DetectEncodingItemArray.size(),sizeof(tagDetectEncodingItem),tagDetectEncodingItem::compare);
		}
		const tagDetectEncodingItem& MostTrustedDetectEncodingItem=DetectEncodingItemArray.at(DetectEncodingItemArray.size()-1);
		const qstring& strEncName=MostTrustedDetectEncodingItem.strEncName;

		if (bTryToRerecognizeUnicodeString)
		{
			if (si.type==ASCSTR_UNICODE)
			{
				if ( (bSystemPlatformUnicodeIsUTF16LE && strEncName=="UTF-16LE")
					||(!bSystemPlatformUnicodeIsUTF16LE && strEncName=="UTF-16BE")
					)
				{
					return FALSE;
				}
			}
		}

		//ִ�����ñ���
		DWORD dwItemValue_EncodeIndex=add_encoding(strEncName.c_str());
		DWORD ItemValue1,ItemValue2;
		DWORD ItemValueM;
		nodeidx_t num=si.ea;
		if ( netnode_supval(num, 16, &ItemValueM, 4, atag) <= 0 )
			ItemValue2 = -1;
		else
			ItemValue2 = ItemValueM - 1;
		ItemValue1 = ItemValue2;
		ItemValueM = (ItemValue2 & 0xFFFFFF | (dwItemValue_EncodeIndex << 24)) + 1;
		netnode_supset(num, 16, &ItemValueM, 4, atag);


		//����si_last_modified
		size_t szCStyleStringLengthIDA=get_max_ascii_length(si.ea,si.type,ALOPT_IGNHEADS|ALOPT_IGNPRINT);
		_ASSERT(szCStyleStringLengthIDA==si.length);
		si_last_modified=si;
		si_last_modified.length=szCStyleStringLengthIDA;
		return TRUE;
	}
	return FALSE;
}

int SetToLocalAnsiCodePage()
{
	UINT uiLocalAnsiCodePage=0;
	//_locale_t localInfo=_get_current_locale();//localInfo->mbcinfo->mbcodepage
	uiLocalAnsiCodePage=GetSystemPlatformAnsiCodePage();
	if (!uiLocalAnsiCodePage)
	{
		warning("can't get local ANSI code page ,please implement it!");
		return 0;
	}
	char szLocalAnsiCodePage[32];
	qsnprintf(szLocalAnsiCodePage,_countof(szLocalAnsiCodePage),"CP%u",uiLocalAnsiCodePage);//��׿,IOS�ȿ�����Ҫ���ó�UTF8
	const char* pszDefEncName=encoding_from_strtype(ASCSTR_C);
	const char* pszDefEncNameW=encoding_from_strtype(ASCSTR_UNICODE);
	int nCount=get_encodings_count();
	bool bFindLocalAnsiCodePage=false;
	for (int i=0;i<nCount;i++)
	{
		const char* pszEncName=get_encoding_name(i);
		if (pszEncName)
		{
			if (!qstrcmp(pszEncName,szLocalAnsiCodePage))
			{
				bFindLocalAnsiCodePage=true;
			}
		}
	}
	if (!bFindLocalAnsiCodePage)
	{
		int iNewItem=add_encoding(szLocalAnsiCodePage);
		set_default_encoding_idx(ASCSTR_C,iNewItem);
		if (SystemPlatformUnicodeIsUTF16LE())//ASCSTR_UNICODE,IDAĬ�ϵ���UTF-16BE
		{
			set_default_encoding_idx(ASCSTR_UNICODE,add_encoding("UTF-16LE"));
		}
		msg("--------------------------------------------------------------------------------------\n");
		msg("AutoSetToLocalAnsiCodePage V2 has helped you to set default code page to %s.\n",szLocalAnsiCodePage);
		msg("--------------------------------------------------------------------------------------\n");
	}

	return 1;
}

//--------------------------------------------------------------------------
// This callback is called for UI notification events
static int idaapi sample_callback(void * /*user_data*/, int event_id, va_list /*va*/)
{
	if (event_id==ui_database_inited)
	{
		SetToLocalAnsiCodePage();
	}
	else if (event_id==processor_t::auto_empty_finally)
	{
		BOOL bTryToRerecognizeUnicodeString=TRUE;
		UINT uiLocalAnsiCodePage=GetSystemPlatformAnsiCodePage();
		BOOL bSystemPlatformUnicodeIsUTF16LE=SystemPlatformUnicodeIsUTF16LE();

		//MLang
#ifdef __NT__
		IStream* (WINAPI * _SHCreateMemStream)(const BYTE * pInit, UINT cbInit) = (IStream * (__stdcall *)(const BYTE *, UINT))GetProcAddress(GetModuleHandle(_T("Shlwapi.dll")), MAKEINTRESOURCEA(12));
		if (_SHCreateMemStream == NULL)
		{
			warning(_T("���򼴽��˳�����Ϊ�޷��ҵ�Shlwapi.dll��SHCreateMemStream������"));
			exit(1);
			return 3;
		}
		IStreamPtr spIStream = _SHCreateMemStream(NULL, 0);
		if (!spIStream)
		{
			warning(_T("���򼴽��˳�����Ϊ�޷�����spIStream����"));
			exit(1);
			return 4;
		}

		ULARGE_INTEGER libInitSize={1024,0};
		spIStream->SetSize(libInitSize);//���ó�ʼʱ��������Ĵ�С

		IMultiLanguagePtr spMultiLanguage;
		HRESULT hr = spMultiLanguage.CreateInstance(__uuidof(CMultiLanguage));
		if (FAILED(hr))
		{
			warning(_T("���򼴽��˳�����Ϊ�޷�����CMultiLanguage����"));
			exit(1);
			return 4;
		}

		IMultiLanguage2Ptr spMultiLanguage2=spMultiLanguage;
		_ASSERT(spMultiLanguage2);
#endif//__NT__

		//ICU
		UCharsetDetector* csd;
		UErrorCode status = U_ZERO_ERROR;
		csd = ucsdet_open(&status);

		//��ʼʶ��ʱֻʶ����ֲ�ͬ��UTF����
		//ע��ICUĿǰ��֧��ʶ��UTF7,����MLang֧��
		UEnumeration *e = ucsdet_getDetectableCharsets(csd, &status);
		int32_t count = uenum_count(e, &status);
		for(int32_t i = 0; i < count; i += 1) 
		{
			int32_t length;
			const char *name = uenum_next(e, &length, &status);

			printf("%d %s\r\n",i,name);

			if (strncmp(name,"UTF-",4))
			{
				ucsdet_setDetectableCharset(csd,name,false,&status);
			}
			else if (!strncmp(name,"UTF-8",6))//�����Լ�ʶ��UTF8
			{
				ucsdet_setDetectableCharset(csd,name,false,&status);
			}

			if(name == NULL || length <= 0) {
				ATLTRACE("ucsdet_getAllDetectableCharsets() returned a null or empty name!\n");
			}
		}

		uenum_close(e);

		//��ʼ����ַ����б�
		string_info_t si_last_modified=0;
		refresh_strlist(inf.minEA,inf.maxEA);
		size_t sCount=get_strlist_qty();
		for (size_t i=0;i<sCount;i++)
		{
			string_info_t si;
			bool bRet=get_strlist_item(i,&si);
			_ASSERT(bRet);

			TryToRerecognizeStringItem(i,si,si_last_modified,
				bTryToRerecognizeUnicodeString,uiLocalAnsiCodePage,bSystemPlatformUnicodeIsUTF16LE,
				spMultiLanguage2,spIStream,
				csd);
		}

		ucsdet_close(csd);
		csd=NULL;

		msg("--------------------------------------------------------------------------------------\n");
		msg("AutoSetToLocalAnsiCodePage V2 has helped you to recognize all string to their charset.\n");
		msg("--------------------------------------------------------------------------------------\n");
	}

	//if ( event_id != ui_msg )     // avoid recursion
	//  if ( event_id != ui_obsolete_setstate
	//    && event_id != ui_obsolete_showauto
	//    && event_id != ui_refreshmarked ) // ignore uninteresting events
	//                  msg("ui_callback %d\n", event_id);
	return 0;                     // 0 means "process the event"
	// otherwise the event would be ignored
}

//--------------------------------------------------------------------------
// A sample how to generate user-defined line prefixes
#if 0
static const int prefix_width = 8;

static void get_user_defined_prefix(ea_t ea,
	int lnnum,
	int indent,
	const char *line,
	char *buf,
	size_t bufsize)
{
	buf[0] = '\0';        // empty prefix by default

	// We want to display the prefix only the lines which
	// contain the instruction itself

	if ( indent != -1 ) return;           // a directive
	if ( line[0] == '\0' ) return;        // empty line
	if ( tag_advance(line,1)[-1] == ash.cmnt[0] ) return; // comment line...

	// We don't want the prefix to be printed again for other lines of the
	// same instruction/data. For that we remember the line number
	// and compare it before generating the prefix

	static ea_t old_ea = BADADDR;
	static int old_lnnum;
	if ( old_ea == ea && old_lnnum == lnnum ) return;

	// Ok, seems that we found an instruction line.

	// Let's display the size of the current item as the user-defined prefix
	asize_t our_size = get_item_size(ea);

	// We don't bother about the width of the prefix
	// because it will be padded with spaces by the kernel

	qsnprintf(buf, bufsize, " %ld", our_size);

	// Remember the address and line number we produced the line prefix for:
	old_ea = ea;
	old_lnnum = lnnum;

}
#endif

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function every time when the plugin gets
//      loaded in the memory.
//      If this function returns PLGUIN_SKIP when called the first time,
//      IDA will never load it again. If it returns PLUGIN_OK, IDA will
//      unload the plugin but remember that the plugin agreed to work with
//      the database. The plugin will be loaded again if the user invokes
//      it by pressing its hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
//      In this example we check the input file format and make the decision.
//      You may or may not check any other conditions to decide what you do:
//      whether you agree to work with the database or not.
//
int idaapi init(void)
{
	//�����ų�ELF�ļ�
	//if ( inf.filetype == f_ELF ) return PLUGIN_SKIP;

#ifdef __NT__
	CoInitialize(NULL);
#endif

	// Please uncomment the following line to see how the notification works
	bool bRet=hook_to_notification_point(HT_UI, sample_callback, NULL);
	bRet=hook_to_notification_point(HT_IDP, sample_callback, NULL);
	//  PLUGIN.flags &= ~PLUGIN_UNL;

	// Please uncomment the following line to see how to the user-defined prefix works
	//  set_user_defined_prefix(prefix_width, get_user_defined_prefix);

	// Please uncomment the following line to see how to define IDC functions
	//  set_idc_func_ex("MyFunc5", myfunc5, myfunc5_args, 0);

	const char *options = get_plugin_options("AutoSetToLocalAnsiCodePage");
	if ( options != NULL )
		warning("command line options: %s", options);

	return (PLUGIN.flags & PLUGIN_UNL) ? PLUGIN_OK : PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
//      Terminate.
//      Usually this callback is empty.
//      The plugin should unhook from the notification lists if
//      hook_to_notification_point() was used.
//
//      IDA will call this function before unloading the plugin.

void idaapi term(void)
{
	unhook_from_notification_point(HT_UI, sample_callback);
	unhook_from_notification_point(HT_IDP, sample_callback);
	//set_user_defined_prefix(0, NULL);
	//set_idc_func_ex("MyFunc5", NULL, NULL, 0);

#ifdef __NT__
	CoUninitialize();
#endif
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user selects the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.
//
//

void idaapi run(int arg)
{
	//warning("plugin \"line_prefixes\" is called with arg %x\n", arg);
	////get_ascii_contents2 ea2str str2user print_ascii_string_type
	////areacb_t_get_area
	//msg("just fyi: the current screen address is: %a\n", get_screen_ea());

	warning(PLUGIN.comment);

	if (ASKBTN_YES==askyn_c(ASKBTN_NO,"Do you want to recognize the strings in IDA string list right now?\r\nif do,it might overwrite user marked data!"))
	{
		sample_callback(0,processor_t::auto_empty_finally,0);
	}
}

//--------------------------------------------------------------------------
static const char comment[] = "AutoSetToLocalAnsiCodePage is a plugin which improve IDA string encoding recognition ability.";

static const char help[] =
	"AutoSetToLocalAnsiCodePage plugin module\n"
	"\n"
	"This module work automaticly.\n";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

static const char wanted_name[] = "AutoSetToLocalAnsiCodePage";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

static const char wanted_hotkey[] = "";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_PROC,           // plugin flags
	init,                 // initialize

	term,                 // terminate. this pointer may be NULL.

	run,                  // invoke plugin

	comment,              // long comment about the plugin
	// it could appear in the status line
	// or as a hint

	help,                 // multiline help about the plugin

	wanted_name,          // the preferred short name of the plugin
	wanted_hotkey         // the preferred hotkey to run the plugin
};
