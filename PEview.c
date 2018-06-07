#include<stdio.h>
#include<windows.h>
DWORD NT_HEADERS;
DWORD EPRVA;
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
int main(void)
{
	char FileName[1001] = {0};
	unsigned char *PEFile = NULL;

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
	OutPutDOSHeader(PEFile);//输出IMAGE_DOS_HEADER
	OutPutDOSSTUB(PEFile);//输出DOS_STUB
	OutPutNTHeaders(PEFile);//输出IMAGE_NT_HEADERS

	system("pause");
	return 0;
}
