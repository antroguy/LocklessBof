#include <Shlobj.h>
#include <Windows.h>
#include "base\helpers.h"
#include "base\ntdefs.h"
#include <shlwapi.h>
#include <ntstatus.h>
#include <time.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <WinUser.h>
#ifdef _DEBUG

#pragma comment (lib, "shell32.lib")
#pragma comment (lib, "Shlwapi.lib")
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif
#pragma comment (lib, "Psapi.lib")
#define CALLBACK_FILE 0x02
#define CALLBACK_FILE_WRITE 0x08
#define CALLBACK_FILE_CLOSE 0x09
#define CHUNK_SIZE 0xe1000
PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName) {
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}


extern "C" {
#include "beacon.h"
    void convertToLowercase(wchar_t* buffer);
    //Ran into overload issues when using DFR Macro for wcsstr/time. Switched to manual resolution isntead of using Macro for these two methods.
#ifndef _DEBUG
    WINBASEAPI wchar_t* __cdecl MSVCRT$wcsstr(const wchar_t* _Str, const wchar_t* _SubStr);
#define wcsstr MSVCRT$wcsstr
    WINBASEAPI time_t __cdecl MSVCRT$time(time_t* time);
#define time MSVCRT$time
    //wcstombs_s(&convertedChars, fileNameChar, bufferSize + 1, fileName.Buffer, bufferSize);
    WINBASEAPI int __cdecl MSVCRT$wcstombs_s(size_t* preturnValue, char* mbstr, size_t sizeInBytes, const wchar_t* wcstr, size_t count);
#define wcstombs_s MSVCRT$wcstombs_s
#endif
    //KERNEL32 DFR
    DFR(KERNEL32, GetFileType);
    DFR(KERNEL32, K32GetProcessImageFileNameW);
    DFR(KERNEL32, GetLastError);
    DFR(KERNEL32, GetProcAddress);
    DFR(KERNEL32, GetModuleHandleA);
    DFR(KERNEL32, OpenProcess);
    DFR(KERNEL32, CloseHandle);
    DFR(KERNEL32, GetCurrentProcess);
    DFR(KERNEL32, HeapAlloc)
    DFR(KERNEL32, GetProcessHeap);
    DFR(KERNEL32, HeapReAlloc);
    DFR(KERNEL32, HeapFree);
    DFR(KERNEL32, GlobalAlloc);
    DFR(KERNEL32, ReadFile);
    DFR(KERNEL32, SetFilePointer);
    DFR(KERNEL32, GetFileSize);
    //MSVCRT DFR
    DFR(MSVCRT, wcstombs)
    DFR(MSVCRT, wcscmp)
    DFR(MSVCRT, wcslen)
    DFR(MSVCRT, memset);
    //KERNEL32 Definitions
    #define GetFileType KERNEL32$GetFileType
    #define GetProcessImageFileNameW KERNEL32$K32GetProcessImageFileNameW
    #define GetLastError KERNEL32$GetLastError
    #define GetProcAddress KERNEL32$GetProcAddress
    #define GetModuleHandleA KERNEL32$GetModuleHandleA
    #define OpenProcess KERNEL32$OpenProcess
    #define CloseHandle KERNEL32$CloseHandle
    #define GetCurrentProcess KERNEL32$GetCurrentProcess
    #define HeapAlloc KERNEL32$HeapAlloc
    #define GetProcessHeap KERNEL32$GetProcessHeap
    #define HeapReAlloc KERNEL32$HeapReAlloc
    #define HeapFree KERNEL32$HeapFree
    #define GlobalAlloc KERNEL32$GlobalAlloc
    #define ReadFile KERNEL32$ReadFile
    #define SetFilePointer KERNEL32$SetFilePointer
    #define GetFileSize KERNEL32$GetFileSize
    //MSVCRT Definitions
    #define wcstombs MSVCRT$wcstombs
    #define wcscmp MSVCRT$wcscmp
    #define wcslen MSVCRT$wcslen
    #define memset MSVCRT$memset


    void go(char* buf, int len) {
        //Local Variables
        DWORD pid = 0;
        wchar_t* filename = NULL;
        wchar_t* processName = NULL;
        datap parser;
        BOOL Success = false;


        //Parse Beacon Arguments
        BeaconDataParse(&parser, buf, len);
        filename = (wchar_t*)BeaconDataExtract(&parser, NULL);
        size_t filenameLen = wcslen(filename);
        processName = NULL;
        processName = (wchar_t*)BeaconDataExtract(&parser, NULL);
        size_t processLen = wcslen(processName);

        //Checks if process name was provided
        if (processName == NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "Attempting to enumerate file handle to % .*S ", filenameLen, filename);
        }
        else {
            //BeaconPrintf(CALLBACK_OUTPUT, "Attempting to enumerate file handle to % .*S ", filenameLen, filename);
            BeaconPrintf(CALLBACK_OUTPUT, "Attempting to enumerate handle to file % .*S from % .*S processes", filenameLen, filename,processLen,processName);
            convertToLowercase(processName);
        }
        
        //Handle variables
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
        int prevPID = 0; //This is used to avoid having to open a handle to the same process more than once
        for (int i = 0; i < handleInfo->HandleCount; i++) {
            //Allocate memory for handle table entry info
            SYSTEM_HANDLE_TABLE_ENTRY_INFO objHandle;
            memset(&objHandle, 0, sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
            objHandle = handleInfo->Handles[i];

            //If the UniqueProcessID is not equal to the previous PID, we already have attempted to open a handle to the process. Just skip.
            if (handleInfo->Handles[i].UniqueProcessId != prevPID) {
                prevPID = handleInfo->Handles[i].UniqueProcessId;
                //If the current PID is not equal to the previous PID, clean up the handle and obtain a handle to the new process 
                if (processHandle) {
                    NtClose(processHandle);
                    processHandle = NULL;
                }
                processHandle = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, handleInfo->Handles[i].UniqueProcessId);

                //If null, go to next handle
                if (NULL == processHandle) {
                    continue;
                }
                //Check if a process name was provided. If so, only check handles in a process that includes the name provided.
                WCHAR imageFileName[MAX_PATH];
                if (processName) {
                    GetProcessImageFileNameW(processHandle, imageFileName, 260);
                    
                    if (GetProcessImageFileNameW(processHandle, imageFileName, MAX_PATH) > 0) {
                        // Extract the process name from the full path
                        wchar_t* processImageName = imageFileName;

                        // Find the last occurrence of the path separator '\'
                        for (int i = wcslen(processImageName) - 1; i >= 0; i--) {
                            if (imageFileName[i] == '\\') {
                                // Set the file name to the portion of the string after the last '\'
                                processImageName = (PWSTR)(imageFileName + i + 1);
                                break;
                            }
                        }
                        // Convert to Lower just in case. 
                        convertToLowercase(processImageName);
                        // Check if the provided process name exists within the target process name
                        if (!wcsstr(processImageName, processName)) {
                            processHandle = NULL;
                            continue;
                        }
                    }
                }
            }
            else {
                //If the current handles PID was equal to the previous PID and we failed to open a handle to it, it will be NULL. We catch that here and continue on to the next handle.  
                if (NULL == processHandle) {
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
            dwErrorCode = (DWORD)NtDuplicateObject(processHandle, (HANDLE)handleInfo->Handles[i].HandleValue, GetCurrentProcess(), &dupHandle, 0, false, DUPLICATE_SAME_ACCESS);

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
            dwErrorCode = (DWORD)NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL);
            //Check if the object type was successfully queries
            if (dwErrorCode != STATUS_SUCCESS) {
                continue;
            }

            //Allocate memory for object name info structure
            objectNameInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
            if (objectNameInfo == NULL) {
                continue;
            }

            //Retrieve object name info
            dwErrorCode = (DWORD)NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength);
            if (dwErrorCode != STATUS_SUCCESS) {

                // Reallocate the buffer and try again.
                objectNameInfo = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objectNameInfo, returnLength);
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

                // Initialize the file name as an empty string
                wchar_t* handleName = NULL;;
                // Find the last occurrence of the path separator '\'
                for (int i = objectName.Length / sizeof(wchar_t) - 1; i >= 0; i--) {
                    if (objectName.Buffer[i] == '\\') {
                        // Set the file name to the portion of the string after the last '\'
                        handleName = (PWSTR)(objectName.Buffer + i + 1);
                        break;
                    }
                }

                // Check if the provided file name exists within the unicodeString
                int result = 0;
                if (filename != NULL) {
                    UNICODE_STRING substring;
                    RtlInitUnicodeString(&substring, filename);
                    result = wcscmp(handleName, filename);
                    if (!result) {
                        Success = true;
                        BeaconPrintf(CALLBACK_OUTPUT, "Process ID %ld [Handle ID% #d] - % .*S [% .*S]\n", handleInfo->Handles[i].UniqueProcessId, handleInfo->Handles[i].HandleValue,wcslen(handleName),handleName, objectName.Length / 2, objectName.Buffer);
                    }
                }

            }

        }
        if (Success == false) {
            BeaconPrintf(CALLBACK_OUTPUT, "Error: Failed to find identify a handle to the specified file");
        }


    //Perform Cleanup
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
    void convertToLowercase(wchar_t* buffer) {
        size_t i = 0;

        for (size_t i = 0; i < wcslen(buffer); ++i) {
            // Check if the character is an uppercase letter
            if (buffer[i] >= L'A' && buffer[i] <= L'Z') {
                // Convert to lowercase by adding the difference between uppercase and lowercase
                buffer[i] = buffer[i] + (L'a' - L'A');
            }
            // Note: If the character is not an uppercase letter, it remains unchanged
        }
    }


}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    //bof::runMocked<int, wchar_t*, wchar_t*>(go, 6696, L"filename", L"Cookies");

    bof::runMocked<wchar_t*,wchar_t*>(go, L"Cookies",L"Chrome");
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
    //ASSERT_EQ(expected.size(), got.size());
    //ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif
