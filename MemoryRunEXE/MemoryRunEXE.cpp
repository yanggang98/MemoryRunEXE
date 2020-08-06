// MemoryRunEXE.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
using namespace std;


//解析PE文件
BOOL readPEInfo(
    PIMAGE_DOS_HEADER &dosHeader,
    PIMAGE_FILE_HEADER &fileHeader, 
    PIMAGE_OPTIONAL_HEADER &optionalHeader,
    PIMAGE_SECTION_HEADER &sectionHeader,
    PCHAR filePath)
{
    FILE** l_file =(FILE**)malloc(sizeof(FILE *));
    PBYTE  pBuffer;
    long fileSize;

    fopen_s(l_file, filePath,"rb");
    //将读取文件指针的位置设为最后
    fseek(*l_file, 0, SEEK_END);
    //读取文件大小
    fileSize = ftell(*l_file);
    std::cout <<hex<<fileSize<<endl;
    //重新设置文件读取指针的位置
    fseek(*l_file, 0, SEEK_SET);
    //申请文件大小的缓冲区
    pBuffer = (PBYTE)malloc(fileSize);
    //将文件内容读取到缓冲区内
    fread(pBuffer, fileSize, 1, *l_file);
    //得到dos的地址
    dosHeader = (PIMAGE_DOS_HEADER)pBuffer;
    //得到file头
    fileHeader = (PIMAGE_FILE_HEADER)(pBuffer + dosHeader->e_lfanew+0x4);
    //得到可选头
    optionalHeader = (PIMAGE_OPTIONAL_HEADER)(pBuffer + dosHeader->e_lfanew + 0x18);
    //得到节区头
    sectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)optionalHeader + fileHeader->SizeOfOptionalHeader);

    if (dosHeader->e_magic != 0x5a4d) 
    {
        cout << "没有DOS头" << endl;
        return false;
    }
    if ((DWORD)*(DWORD *)(pBuffer + dosHeader->e_lfanew) != 0x4550) 
    {
        cout << "没有PE头" << endl;
        return false;
    }

    cout << hex <<fileHeader->Machine<<endl ;
    cout << hex <<optionalHeader->AddressOfEntryPoint<<endl ;
    cout << hex <<sectionHeader->Name<<endl ;

    free(l_file);
    return true;

}
//返回文件所占用的内存空间
long getImageSize(PIMAGE_OPTIONAL_HEADER optionalHeader)
{
    return optionalHeader->SizeOfImage;
}


//返回对齐后的内存大小
unsigned long getAlignedSize(unsigned long size,unsigned long alignment)
{
    if (size % alignment==0)
    {
        return size;
    }
    else
    {
        int val = size / alignment;
        val++;
        return val * alignment;
    }
}

//将文件加载到内存中
BOOL loadPE(
    PIMAGE_DOS_HEADER dosHeader,
    PIMAGE_FILE_HEADER fileHeader,
    PIMAGE_OPTIONAL_HEADER optionalHeader,
    PIMAGE_SECTION_HEADER  sectionHeader,
    PBYTE &buffer)
{

    //申请空间
    PBYTE pBuffer = (PBYTE)(PBYTE)VirtualAlloc(NULL,
        getImageSize(optionalHeader),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (pBuffer==NULL) 
    {
        //内存空间申请失败

        return false;
    }

    //得到文件头的大小
    int headerSize = optionalHeader->SizeOfHeaders;
    //得到内存中文件头对齐后的大小
    long index=getAlignedSize(headerSize, optionalHeader->SectionAlignment);
    //将文件头映射到内存中
    memcpy(pBuffer, dosHeader, headerSize);

    for (int i = 0; i < fileHeader->NumberOfSections; i++) 
    {
        //判断文件的节是否为空
        if(sectionHeader[i].SizeOfRawData!=0)
        {
                //将节区的内容加载到内存中
                memcpy(pBuffer + index, ((PBYTE)dosHeader)+ sectionHeader[i].PointerToRawData , sectionHeader[i].SizeOfRawData);
                index += getAlignedSize(sectionHeader[i].Misc.VirtualSize, optionalHeader->SectionAlignment);
        }
        else
        {
            if (sectionHeader[i].Misc.VirtualSize) 
            {
                index += getAlignedSize(sectionHeader[i].Misc.VirtualSize, optionalHeader->SectionAlignment);
            }

        }
    }
    buffer = pBuffer;
    return true;
}

//创建进程 
//获取想过的进程信息
// base 进程加载的实际地址
// size 进程加载的内存大小
BOOL createPro(PCONTEXT ctx, PPROCESS_INFORMATION pi,DWORD &base,DWORD &size)
{
    STARTUPINFO si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = TRUE;

    //壳exe路径
    TCHAR szCmdLine[] = { TEXT("D:\\Software\\吾爱破解工具包\\Tools\\Others\\ipmsg.exe") };
    //创建进程以挂起的方式
    if (CreateProcess(NULL,(LPWSTR)szCmdLine,NULL,NULL,0, CREATE_SUSPENDED,NULL,NULL,&si,pi))
    {
        ctx->ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi->hThread, ctx);
        SIZE_T num;
        DWORD curAddr;
        DWORD ImageBase;
        DWORD ImageSize;
        MEMORY_BASIC_INFORMATION memInfo = {0};

        ReadProcessMemory(pi->hProcess, ((DWORD*)(ctx->Ebx))+2, &ImageBase, sizeof(DWORD), &num);
        //获取进程加载的基址
        cout << hex<< ImageBase <<endl;
        //在 SVCHOST.EXE中寻找 MEM_FREE 的内存地址
        curAddr = ImageBase;
        while (VirtualQueryEx(pi->hProcess, (LPVOID)curAddr, &memInfo, sizeof(memInfo)))
        {
            if (memInfo.State == MEM_FREE)
                break;
            curAddr += memInfo.RegionSize;
        }
        //获取进程内存大小
        ImageSize = curAddr - ImageBase;
        cout << hex << ImageSize <<endl;
        base = ImageBase;
        size = ImageSize;
    }
    else 
    {
        cout << "创建进程失败";
        return false;
    }
    return true;
}




// 重定位
void doRelocation(
    PIMAGE_DOS_HEADER dosHeader,
    PIMAGE_FILE_HEADER fileHeader,
    PIMAGE_OPTIONAL_HEADER optionalHeader,
    PIMAGE_SECTION_HEADER  sectionHeader,
    PBYTE buffer,
    DWORD newAddress)
{
    PIMAGE_DATA_DIRECTORY  l_PDateDirectory;
    long change;
    l_PDateDirectory = optionalHeader->DataDirectory;
    //判断是否存在基址重定位表
    if (l_PDateDirectory[5].Size && l_PDateDirectory[5].VirtualAddress) 
    {
        PIMAGE_BASE_RELOCATION l_pBaeRelocation = (PIMAGE_BASE_RELOCATION)(buffer + l_PDateDirectory[5].VirtualAddress);
        
        DWORD l_word = (DWORD)l_pBaeRelocation;
        PBYTE  l_pBase = (PBYTE)l_pBaeRelocation;
        DWORD size = (DWORD)((DWORD)l_pBaeRelocation + (l_PDateDirectory[5].Size));
        //遍历所有的需要改变的基址
        while ((DWORD)l_pBase < size)
        {
            l_word += 8;
            //遍历每一个块
            while (((DWORD)l_pBase +(((PIMAGE_BASE_RELOCATION)l_pBase)->SizeOfBlock))>l_word)
            {
              
              WORD *p=  (WORD *)(l_word);
              //判断重定位的类型
              if (((*p) & 0xF000) == 0x3000) 
              {
                  DWORD* changeAddress = (DWORD*)(buffer + ((PIMAGE_BASE_RELOCATION)l_pBase)->VirtualAddress + ((*p)&0x0fff));
                  change = newAddress - optionalHeader->ImageBase;
                  *changeAddress += change;
              }
              l_word += 2;
            }
            l_pBase += ((PIMAGE_BASE_RELOCATION)l_pBase)->SizeOfBlock;
            l_word = (DWORD)l_pBase;
        }

    
    }
    else 
    {
        cout << "没有重定位表";
    }
   
}

//修改导入表
void changeImportTable(
    PIMAGE_DOS_HEADER dosHeader,
    PIMAGE_FILE_HEADER fileHeader,
    PIMAGE_OPTIONAL_HEADER optionalHeader,
    PIMAGE_SECTION_HEADER  sectionHeader,
    PBYTE buffer)
{
    PIMAGE_DATA_DIRECTORY  l_PDateDirectory;
    long change;
    l_PDateDirectory = optionalHeader->DataDirectory;
    HMODULE hall;
    PIMAGE_IMPORT_DESCRIPTOR l_pDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(buffer + l_PDateDirectory[1].VirtualAddress);

    //遍历所有的导入
    while (l_pDescriptor->Name != 0x0) 
    {
        PCHAR name = (PCHAR)(buffer + l_pDescriptor->Name);
        
        //获取相关的dll句柄
        hall = GetModuleHandleA(name);

        if (hall == NULL) 
        {
            //手动加载相关的dll
            hall = LoadLibraryA(name);
            if (hall == NULL ) 
            {
                l_pDescriptor++;
                continue;
            }
        }

        PIMAGE_THUNK_DATA functionNameArray=(PIMAGE_THUNK_DATA)(buffer + l_pDescriptor->OriginalFirstThunk);
        PIMAGE_THUNK_DATA functionAddressArray = (PIMAGE_THUNK_DATA)(buffer + l_pDescriptor->FirstThunk);
        FARPROC lpFuncAddress = NULL;
        int i = 0;
        while (functionNameArray[i].u1.AddressOfData != 0) 
        {
            //是否是名称导入
            if ((functionNameArray[i].u1.Ordinal & 0x80000000) == 0) 
            {
                PIMAGE_IMPORT_BY_NAME  functionName = (PIMAGE_IMPORT_BY_NAME)(buffer + functionNameArray[i].u1.AddressOfData);
                //名称导入函数地址
                lpFuncAddress = GetProcAddress(hall,(LPCSTR)functionName->Name);

                //cout << functionName->Name<<"  "<<hex<<(DWORD)lpFuncAddress<<endl;
            }
            else 
            {
                //序号导入函数地址
                lpFuncAddress = GetProcAddress(hall, (LPCSTR)(functionNameArray[i].u1.Ordinal & 0x0000FFFF));
            }
            functionAddressArray[i].u1.Function = (DWORD)lpFuncAddress;
            i++;

        }
        l_pDescriptor++;
    }

}


//将源程序放入目标程序
void doFork(
    PIMAGE_DOS_HEADER dosHeader,
    PIMAGE_FILE_HEADER fileHeader,
    PIMAGE_OPTIONAL_HEADER optionalHeader,
    PIMAGE_SECTION_HEADER  sectionHeader,
    PBYTE buffer)
{
    CONTEXT ctx = {0};
    PROCESS_INFORMATION pi = {0};
    DWORD base;
    DWORD size;
    if (createPro(&ctx, &pi, base, size)) 
    {
        if (optionalHeader->SizeOfImage <= size) 
        {        
            //修改导入表
            changeImportTable(dosHeader, fileHeader, optionalHeader, sectionHeader, buffer);
            //修改目标进程内存空间的地址权限
            DWORD oldProtect;
            if (!VirtualProtectEx(pi.hProcess, (LPVOID)(optionalHeader->ImageBase), optionalHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect)) 
            {
                cout << "权限修改失败";
            };
            //写入目标进程
            if (!WriteProcessMemory(pi.hProcess, (LPVOID)(optionalHeader->ImageBase), buffer, optionalHeader->SizeOfImage, NULL)) 
            {
                cout << "写入目标进程失败";
            };
            //修改寄存器的值
            ctx.ContextFlags = CONTEXT_FULL;
            ctx.Eax = (optionalHeader->ImageBase) + (optionalHeader->AddressOfEntryPoint);
            SetThreadContext(pi.hThread, &ctx);
            //恢复进程
            ResumeThread(pi.hThread);
        }
        else 
        {
            cout << "源程序太大";
        }
    }
    else 
    {
        cout << "创建壳进程失败";
    }
}

//C:\\Windows\\System32\\notepad.exe
//E:\\PEView\\PEView.exe （没有重定位表）
//E:\\NikPEViewer.exe
//D:\\Software\\吾爱破解工具包\\Tools\\Others\\ipmsg.exe(没有重定位表)
//D:\\逆向工程\\逆向科普\\练习\\FirstWindow.exe
//D:\\逆向工程\\逆向科普\\练习\\serial.exe
//C:\\Program Files\\Tencent\\QQ\\Bin\\QQScLauncher.exe
//D:\\逆向工程\\逆向科普\\练习\\1.CrackMe.exe
int main()
{  
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_FILE_HEADER fileHeader;
    PIMAGE_OPTIONAL_HEADER optionalHeader;
    PIMAGE_SECTION_HEADER sectionHeader;
    CHAR* filePath = (CHAR *)"D:\\逆向工程\\逆向科普\\练习\\FirstWindow.exe";
    readPEInfo(dosHeader,fileHeader,optionalHeader,sectionHeader,filePath);
    PBYTE buffer;
    if (!loadPE(dosHeader, fileHeader, optionalHeader, sectionHeader, buffer)) 
    {
        //加载失败
        return 0;
    };

    doFork(dosHeader, fileHeader, optionalHeader, sectionHeader, buffer);
    return 0;
}

