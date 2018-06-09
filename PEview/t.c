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
	DWORD FileSize;//�ļ���С
	unsigned char *DstBuffer = NULL;//���ڴ��PE�ļ�
	
	fopen_s(&fp,FileName,"rb");
	fseek(fp,0,SEEK_END);
	FileSize = ftell(fp);//��ȡ�ļ���С
	fseek(fp,0,SEEK_SET);
	DstBuffer = (unsigned char*)malloc(FileSize*sizeof(unsigned char));
	fread(DstBuffer,1,FileSize,fp);
	return DstBuffer;
}
int OutPutHexLE(unsigned char *DataBuff,int End,int Begin)
{
	int i,t=0;
	printf("�� ");
	for (i=Begin;i>=End;i--,t++)
	{
		if (t&&(t%10)==0)
			printf("\n�� ");
		printf("%02X ",DataBuff[i]);
	}
	printf("\n");
	return 0;
}
int OutPutHexBE(unsigned char *DataBuff,int Begin,int End)
{
	int i,t=0;
	printf("�� ");
	for (i=Begin;i<=End;i++,t++)
	{
		if (t&&(t%10)==0)
			printf("\n�� ");
		printf("%02X ",DataBuff[i]);
	}
	printf("\n");
	return 0;
}
int OutPutValue(unsigned char *DataBuff,int Begin,int End)
{
	int i,t=0;
	printf("�� ");
	for (i=Begin;i<=End;i++,t++)
	{
		if (t&&(t%10)==0)
			printf("\n�� ");
		if (DataBuff[i]!=10&&DataBuff[i]!=13)//���˻�����ص������ַ�
			printf("%c",DataBuff[i]);
	}
	printf("\n");
	return 0;
}
int OutPutDOSHeader(unsigned char *DataBuff)
{
	printf("IMAGE_DOS_HEADER:\n");
	printf("��Signature(Hex):\n");
	OutPutHexLE(DataBuff,0,1);
	printf("��Signature(Value):\n");
	OutPutHexLE(DataBuff,0,1);
	printf("��Bytes on Last Page of File(Hex):\n");
	OutPutHexLE(DataBuff,2,3);
	printf("��Pages in File(Hex):\n");
	OutPutHexLE(DataBuff,4,5);
	printf("��Relocations(Hex):\n");
	OutPutHexLE(DataBuff,6,7);
	printf("��Size of Header in Paragraphs(Hex):\n");
	OutPutHexLE(DataBuff,8,9);
	printf("��Minimum Extra Paragraphs(Hex):\n");
	OutPutHexLE(DataBuff,10,11);
	printf("��Maximum Extra Paragraphs(Hex):\n");
	OutPutHexLE(DataBuff,12,13);
	printf("��Initial SS(Hex):\n");
	OutPutHexLE(DataBuff,14,15);
	printf("��Initial SP(Hex):\n");
	OutPutHexLE(DataBuff,16,17);
	printf("��Checksum:\n");
	OutPutHexLE(DataBuff,18,19);
	printf("��Initial IP(Hex):\n");
	OutPutHexLE(DataBuff,20,21);
	printf("��Initial CS(Hex):\n");
	OutPutHexLE(DataBuff,22,23);
	printf("��Offset to Relocation Table(Hex):\n");
	OutPutHexLE(DataBuff,24,25);
	printf("��OverLay Number(Hex):\n");
	OutPutHexLE(DataBuff,26,27);
	printf("��Reserved(Hex):\n");
	OutPutHexLE(DataBuff,28,35);
	printf("��OEM identifier(Hex):\n");
	OutPutHexLE(DataBuff,36,37);
	printf("��OEM information(Hex):\n");
	OutPutHexLE(DataBuff,38,39);
	printf("��Reserved(Hex):\n");
	OutPutHexLE(DataBuff,40,58);
	printf("��Offset to New EXE Header(Hex):\n");
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
	printf("��Machine(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+4,NT_HEADERS+5);
	printf("��Number of Sections(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+6,NT_HEADERS+7);
	printf("��Size of Code(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+28,NT_HEADERS+31);
	printf("��Address of EntryPoint(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+40,NT_HEADERS+43);
	printf("��Base of Code(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+44,NT_HEADERS+47);
	printf("��Base of Data(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+48,NT_HEADERS+51);
	printf("��ImageBase(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+52,NT_HEADERS+55);
	printf("��Export Table RVA(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+120,NT_HEADERS+123);
	printf("��Export Table SIZE(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+124,NT_HEADERS+127);
	printf("��Import Table RVA(Hex):\n");
	OutPutHexLE(DataBuff,NT_HEADERS+128,NT_HEADERS+131);
	printf("��Import Table SIZE(Hex):\n");
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
		printf("��VirtualAddress(Hex):\n");
		OutPutHexLE(DataBuff,Section_HeaderRVA[i]+12,Section_HeaderRVA[i]+15);
		printf("��Point to RawData(Hex):\n");
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

	scanf_s("%s",FileName,1000);//�����ļ�����·��
	PEFile = GetFileBin(FileName);//��ȡPE�ļ�
	NT_HEADERS = (PEFile[63]*16*16*16*16*16*16*16*16+
				  PEFile[62]*16*16*16*16+
				  PEFile[61]*16*16+
				  PEFile[60]);//PEͷ��ʼλ��
	EPRVA = (PEFile[NT_HEADERS+43]*16*16*16*16*16*16*16*16+
			 PEFile[NT_HEADERS+42]*16*16*16*16+
			 PEFile[NT_HEADERS+41]*16*16+
			 PEFile[NT_HEADERS+40]);//������ڵ�ַRVA
	Export_Table_DirRVA = PEFile[NT_HEADERS+120]+
						  PEFile[NT_HEADERS+121]*16*16+
						  PEFile[NT_HEADERS+120]*16*16*16*16+
						  PEFile[NT_HEADERS+120]*16*16*16*16*16*16*16*16;//�����������ṹRVA
	Import_Table_DirRVA = PEFile[NT_HEADERS+128]+
						  PEFile[NT_HEADERS+129]*16*16+
						  PEFile[NT_HEADERS+130]*16*16*16*16+
						  PEFile[NT_HEADERS+131]*16*16*16*16*16*16*16*16;//����������ṹRVA
	SectionNum = PEFile[NT_HEADERS+6]+PEFile[NT_HEADERS+7]*16*16;//����
	Section_HeaderRVA = (DWORD*)malloc(SectionNum*sizeof(DWORD));//��ʼ���ڱ�����
	Section_HeaderRVA[0] = NT_HEADERS + 248;
	for (i=1;i<SectionNum;i++)
		Section_HeaderRVA[i] = Section_HeaderRVA[i-1] + 40;//���ڱ�����
	VirtualAddress = (DWORD*)malloc(SectionNum*sizeof(DWORD));//��ʼ����RVA����
	PointerToRawData = (DWORD*)malloc(SectionNum*sizeof(DWORD));//��ʼ����RAW����
	for (i=0;i<SectionNum;i++)
	{//��RVA����RAW���鸳ֵ
		VirtualAddress[i] = PEFile[Section_HeaderRVA[i]+12]+
							PEFile[Section_HeaderRVA[i]+13]*16*16+
							PEFile[Section_HeaderRVA[i]+14]*16*16*16*16+
							PEFile[Section_HeaderRVA[i]+15]*16*16*16*16*16*16*16*16;
		PointerToRawData[i] = PEFile[Section_HeaderRVA[i]+20]+
							  PEFile[Section_HeaderRVA[i]+21]*16*16+
							  PEFile[Section_HeaderRVA[i]+22]*16*16*16*16+
							  PEFile[Section_HeaderRVA[i]+23]*16*16*16*16*16*16*16*16;
	}
	Import_DLL_Num = 0;//����DLL����
	for (i=0;i<SectionNum;i++)//����������ṹRAW��ֵ
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
	OriginalFirstThunkRVA = (DWORD*)malloc(Import_DLL_Num*sizeof(DWORD));//Import Thunk DataRVA�����ʼ��
	OriginalFirstThunkRAW = (DWORD*)malloc(Import_DLL_Num*sizeof(DWORD));//Import Thunk DataRAW�����ʼ��
	for (i=0;i<Import_DLL_Num;i++)
	{
		OriginalFirstThunkRVA[i] = PEFile[Import_Table_DirRAW+20*i]+
								   PEFile[Import_Table_DirRAW+20*i+1]*16*16+
								   PEFile[Import_Table_DirRAW+20*i+2]*16*16*16*16+
								   PEFile[Import_Table_DirRAW+20*i+3]*16*16*16*16*16*16*16*16;//Import Thunk DataRVA����
	}
	for (i=0;i<SectionNum;i++)//Import Thunk DataRVA����
		if (Import_Table_DirRVA<VirtualAddress[i])
			continue;
		else
		{
			for (j=0;j<Import_DLL_Num;j++)
				OriginalFirstThunkRAW[j] = OriginalFirstThunkRVA[j] - VirtualAddress[i] + PointerToRawData[i];
			break;
		}
	for (i=0;i<SectionNum;i++)//����������ṹRAW��ֵ
		if (Export_Table_DirRVA<VirtualAddress[i])
			continue;
		else
			Export_Table_DirRAW = Export_Table_DirRVA - VirtualAddress[i] + PointerToRawData[i];



	OutPutDOSHeader(PEFile);//���IMAGE_DOS_HEADER
	//OutPutDOSSTUB(PEFile);//���DOS_STUB
	//OutPutNTHeaders(PEFile);//���IMAGE_NT_HEADERS
	//OutPutSectionTable(PEFile);//���SECTION_TABLE
	OutPutImport(PEFile);//������������

	system("pause");
	return 0;
}
