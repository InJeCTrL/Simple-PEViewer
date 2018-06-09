#include<stdio.h>
#include<windows.h>
DWORD NT_HEADERS;
DWORD EPRVA;
DWORD Export_Table_DirRVA;
DWORD Export_Table_DirRAW;
DWORD Import_Table_DirRVA;
DWORD Import_Table_DirRAW;
DWORD Import_DLL_Num;
DWORD SectionNum;
DWORD *Section_HeaderRVA;
DWORD *VirtualAddress;
DWORD *PointerToRawData;
DWORD *OriginalFirstThunkRVA;
DWORD *OriginalFirstThunkRAW;
unsigned char* GetFileBin(char *FileName)
{
	FILE *fp;
	DWORD FileSize;//文件大小
	unsigned char *DstBuffer = NULL;//用于存放PE文件
	
	fopen_s(&fp,FileName,"rb");
	fseek(fp,0,SEEK_END);
	FileSize = ftell(fp);//获取文件大小
	fseek(fp,0,SEEK_SET);
	DstBuffer = (unsigned char*)malloc(FileSize*sizeof(unsigned char));
	fread(DstBuffer,1,FileSize,fp);
	return DstBuffer;
}
int OutPutHexLE(unsigned char *DataBuff,int End,int Begin)
{
	int i,t=0;
	printf("┃ ");
	for (i=Begin;i>=End;i--,t++)
	{
		if (t&&(t%10)==0)
			printf("\n┃ ");
		printf("%02X ",DataBuff[i]);
	}
	printf("\n");
	return 0;
}
int OutPutHexBE(unsigned char *DataBuff,int Begin,int End)
{
	int i,t=0;
	printf("┃ ");
	for (i=Begin;i<=End;i++,t++)
	{
		if (t&&(t%10)==0)
			printf("\n┃ ");
		printf("%02X ",DataBuff[i]);
	}
	printf("\n");
	return 0;
}
int OutPutValue(unsigned char *DataBuff,int Begin,int End)
{
	int i,t=0;
	printf("┃ ");
	for (i=Begin;i<=End;i++,t++)
	{
		if (t&&(t%10)==0)
			printf("\n┃ ");
		if (DataBuff[i]!=10&&DataBuff[i]!=13)//过滤换行与回到行首字符
			printf("%c",DataBuff[i]);
	}
	printf("\n");
	return 0;
}
int OutPutDOSHeader(unsigned char *DataBuff)
{
	printf("IMAGE_DOS_HEADER:\n");
	printf("┣Signature(Hex):\n");
	OutPutHexLE(DataBuff,0,1);
	printf("┣Signature(Value):\n");
	OutPutHexLE(DataBuff,0,1);
	printf("┣Bytes on Last Page of File(Hex):\n");
	OutPutHexLE(DataBuff,2,3);
	printf("┣Pages in File(Hex):\n");
	OutPutHexLE(DataBuff,4,5);
	printf("┣Relocations(Hex):\n");
	OutPutHexLE(DataBuff,6,7);
	printf("┣Size of Header in Paragraphs(Hex):\n");
	OutPutHexLE(DataBuff,8,9);
	printf("┣Minimum Extra Paragraphs(Hex):\n");
	OutPutHexLE(DataBuff,10,11);
	printf("┣Maximum Extra Paragraphs(Hex):\n");
	OutPutHexLE(DataBuff,12,13);
	printf("┣Initial SS(Hex):\n");
	OutPutHexLE(DataBuff,14,15);
	printf("┣Initial SP(Hex):\n");
	OutPutHexLE(DataBuff,16,17);
	printf("┣Checksum:\n");
	OutPutHexLE(DataBuff,18,19);
	printf("┣Initial IP(Hex):\n");
	OutPutHexLE(DataBuff,20,21);
	printf("┣Initial CS(Hex):\n");
	OutPutHexLE(DataBuff,22,23);
	printf("┣Offset to Relocation Table(Hex):\n");
	OutPutHexLE(DataBuff,24,25);
	printf("┣OverLay Number(Hex):\n");
	OutPutHexLE(DataBuff,26,27);
	printf("┣Reserved(Hex):\n");
	OutPutHexLE(DataBuff,28,35);
	printf("┣OEM identifier(Hex):\n");
	OutPutHexLE(DataBuff,36,37);
	printf("┣OEM information(Hex):\n");
	OutPutHexLE(DataBuff,38,39);
	printf("┣Reserved(Hex):\n");
	OutPutHexLE(DataBuff,40,58);
	printf("┣Offset to New EXE Header(Hex):\n");
	OutPutHexLE(DataBuff,59,62);
	return 0;
}
int OutPutDOSSTUB(unsigned char *DataBuff)
{
	printf("DOS_STUB(HEX):\n");
	OutPutHexBE(DataBuff,64,NT_HEADERS-1);
	printf("DOS_STUB(Value):\n");
	OutPutValue(DataBuff,64,NT_HEADERS-1);
	return 0;
}
int OutPutNTHeaders(unsigned char *DataBuff)
{
	printf("IMAGE_NT_HEADERS:\n");
	printf("┣Machine(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+4,NT_HEADERS+5);
	printf("┣Number of Sections(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+6,NT_HEADERS+7);
	printf("┣Size of Code(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+28,NT_HEADERS+31);
	printf("┣Address of EntryPoint(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+40,NT_HEADERS+43);
	printf("┣Base of Code(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+44,NT_HEADERS+47);
	printf("┣Base of Data(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+48,NT_HEADERS+51);
	printf("┣ImageBase(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+52,NT_HEADERS+55);
	printf("┣Export Table RVA(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+120,NT_HEADERS+123);
	printf("┣Export Table SIZE(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+124,NT_HEADERS+127);
	printf("┣Import Table RVA(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+128,NT_HEADERS+131);
	printf("┣Import Table SIZE(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+132,NT_HEADERS+135);
	return 0;
}
int OutPutSectionTable(unsigned char *DataBuff)
{
	int i;
	printf("SECTION TABLE:\n");
	for (i=0;i<SectionNum;i++)
	{
		OutPutValue(DataBuff,Section_HeaderRVA[i],Section_HeaderRVA[i]+7);
		printf("┣VirtualAddress(Hex):\n");
		OutPutHexLE(DataBuff,Section_HeaderRVA[i]+12,Section_HeaderRVA[i]+15);
		printf("┣Point to RawData(Hex):\n");
		OutPutHexLE(DataBuff,Section_HeaderRVA[i]+20,Section_HeaderRVA[i]+23);
	}
	return 0;
}
int OutPutImport(unsigned char *DataBuff)
{
	int i,j,k;
	DWORD APINameRVA,APINameRAW;
	printf("IMPORT API:\n");
	for (i=0;i<Import_DLL_Num;i++)
	{
		for (j=OriginalFirstThunkRAW[i];DataBuff[j];j+=4)
		{
			for (k=0;k<SectionNum;k++)//RVAtoRAW
				if ((APINameRVA = DataBuff[j]+DataBuff[j+1]*16*16+2)<VirtualAddress[k])
					continue;
				else
				{
					APINameRAW = APINameRVA - VirtualAddress[k] + PointerToRawData[k];
					break;
				}
			printf("%s\n",&DataBuff[APINameRAW]);
		}

	}
	return 0;
}
int main(void)
{
	char FileName[1001] = {0};
	unsigned char *PEFile = NULL;
	int i,j;

	scanf_s("%s",FileName,1000);//输入文件绝对路径
	PEFile = GetFileBin(FileName);//获取PE文件
	NT_HEADERS = (PEFile[63]*16*16*16*16*16*16*16*16+
				  PEFile[62]*16*16*16*16+
				  PEFile[61]*16*16+
				  PEFile[60]);//PE头起始位置
	EPRVA = (PEFile[NT_HEADERS+43]*16*16*16*16*16*16*16*16+
			 PEFile[NT_HEADERS+42]*16*16*16*16+
			 PEFile[NT_HEADERS+41]*16*16+
			 PEFile[NT_HEADERS+40]);//程序入口地址RVA
	Export_Table_DirRVA = PEFile[NT_HEADERS+120]+
						  PEFile[NT_HEADERS+121]*16*16+
						  PEFile[NT_HEADERS+120]*16*16*16*16+
						  PEFile[NT_HEADERS+120]*16*16*16*16*16*16*16*16;//导出表索引结构RVA
	Import_Table_DirRVA = PEFile[NT_HEADERS+128]+
						  PEFile[NT_HEADERS+129]*16*16+
						  PEFile[NT_HEADERS+130]*16*16*16*16+
						  PEFile[NT_HEADERS+131]*16*16*16*16*16*16*16*16;//导入表索引结构RVA
	SectionNum = PEFile[NT_HEADERS+6]+PEFile[NT_HEADERS+7]*16*16;//节数
	Section_HeaderRVA = (DWORD*)malloc(SectionNum*sizeof(DWORD));//初始化节表数组
	Section_HeaderRVA[0] = NT_HEADERS + 248;
	for (i=1;i<SectionNum;i++)
		Section_HeaderRVA[i] = Section_HeaderRVA[i-1] + 40;//填充节表数组
	VirtualAddress = (DWORD*)malloc(SectionNum*sizeof(DWORD));//初始化节RVA数组
	PointerToRawData = (DWORD*)malloc(SectionNum*sizeof(DWORD));//初始化节RAW数组
	for (i=0;i<SectionNum;i++)
	{//节RVA、节RAW数组赋值
		VirtualAddress[i] = PEFile[Section_HeaderRVA[i]+12]+
							PEFile[Section_HeaderRVA[i]+13]*16*16+
							PEFile[Section_HeaderRVA[i]+14]*16*16*16*16+
							PEFile[Section_HeaderRVA[i]+15]*16*16*16*16*16*16*16*16;
		PointerToRawData[i] = PEFile[Section_HeaderRVA[i]+20]+
							  PEFile[Section_HeaderRVA[i]+21]*16*16+
							  PEFile[Section_HeaderRVA[i]+22]*16*16*16*16+
							  PEFile[Section_HeaderRVA[i]+23]*16*16*16*16*16*16*16*16;
	}
	Import_DLL_Num = 0;//输入DLL个数
	for (i=0;i<SectionNum;i++)//输入表索引结构RAW赋值
		if (Import_Table_DirRVA<VirtualAddress[i])
			continue;
		else
		{
			Import_Table_DirRAW = Import_Table_DirRVA - VirtualAddress[i] + PointerToRawData[i];
			break;
		}
	i = 0;
	while (PEFile[Import_Table_DirRAW+i]||PEFile[Import_Table_DirRAW+i+1]||PEFile[Import_Table_DirRAW+i+2]||PEFile[Import_Table_DirRAW+i+3])
	{
		Import_DLL_Num++;
		i += 20;
	}
	OriginalFirstThunkRVA = (DWORD*)malloc(Import_DLL_Num*sizeof(DWORD));//Import Thunk DataRVA数组初始化
	OriginalFirstThunkRAW = (DWORD*)malloc(Import_DLL_Num*sizeof(DWORD));//Import Thunk DataRAW数组初始化
	for (i=0;i<Import_DLL_Num;i++)
	{
		OriginalFirstThunkRVA[i] = PEFile[Import_Table_DirRAW+20*i]+
								   PEFile[Import_Table_DirRAW+20*i+1]*16*16+
								   PEFile[Import_Table_DirRAW+20*i+2]*16*16*16*16+
								   PEFile[Import_Table_DirRAW+20*i+3]*16*16*16*16*16*16*16*16;//Import Thunk DataRVA数组
	}
	for (i=0;i<SectionNum;i++)//Import Thunk DataRVA数组
		if (Import_Table_DirRVA<VirtualAddress[i])
			continue;
		else
		{
			for (j=0;j<Import_DLL_Num;j++)
				OriginalFirstThunkRAW[j] = OriginalFirstThunkRVA[j] - VirtualAddress[i] + PointerToRawData[i];
			break;
		}
	for (i=0;i<SectionNum;i++)//输出表索引结构RAW赋值
		if (Export_Table_DirRVA<VirtualAddress[i])
			continue;
		else
			Export_Table_DirRAW = Export_Table_DirRVA - VirtualAddress[i] + PointerToRawData[i];



	OutPutDOSHeader(PEFile);//输出IMAGE_DOS_HEADER
	//OutPutDOSSTUB(PEFile);//输出DOS_STUB
	//OutPutNTHeaders(PEFile);//输出IMAGE_NT_HEADERS
	//OutPutSectionTable(PEFile);//输出SECTION_TABLE
	OutPutImport(PEFile);//输出导入表函数名

	system("pause");
	return 0;
}
