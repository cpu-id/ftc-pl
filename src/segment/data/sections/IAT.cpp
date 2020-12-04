#include "SectionAccessor.hpp"

//Full reconstruction of native import address table.
//Author: 0x000cb & original fatal cracker.

std::map <std::string, std::vector <AdditionalRuntime::ImportDefinition>> SectionAccessor::IAT = {

        //WINTRUST.
        { "wintrust",

                {

                    { "WinVerifyTrust",

                      {
                        { AdditionalRuntime::ImportType::PUBLIC, { 0x15F85A } },
                      }

                    }

                }

        },

        //KERNEL32.
        { "kernel32",

                {

                        { "GetFileAttributesW",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, { 0x13EA67, 0x13EBAA, 0x13EF86, 0x15F8CC } }
                          }
                        },

                        { "GetProcAddress",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x1173D8, 0x1175E0, 0x117615, 0x11F082,
                                0x11F28A, 0x11F2BF, 0x126003, 0x126083,
                                0x126103, 0x126183, 0x126203, 0x126283,
                                0x126303, 0x126383, 0x126403, 0x126483,
                                0x126503, 0x126583, 0x126603, 0x126863,
                                0x1268E3, 0x126963, 0x1269E3, 0x126F63,
                                0x127413, 0x13DA77, 0x13DA85, 0x13E26F,
                                0x13F135, 0x13F281, 0x13F39B, 0x14AFA9,
                                0x14B2B7, 0x15F65C

                            } }
                          }
                        },

                        { "CloseHandle",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x267D,   0x26D5,   0x10E57A, 0x10E5D4,
                                0x13DAD4, 0x13E16C, 0x15F5C0

                            } }
                          }
                        },

                        { "GetModuleFileNameA",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x14AFF8, 0x15F950 } } }
                        },

                        { "Beep",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x18D0, 0x15F5A8 } } }
                        },

                        { "VirtualProtect",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x7EA5D,  0x7EA78,  0x7FC84,  0x7FCA6,
                                0x863A6,  0x86418,  0x1164FD, 0x116518,
                                0x117A2F, 0x117A4A, 0x117C7F, 0x117C9A,
                                0x117ECF, 0x117EEA, 0x11835F, 0x11837A,
                                0x11862F, 0x11864A, 0x12423D, 0x124266,
                                0x124536, 0x124559, 0x1247D7, 0x124C5F,
                                0x124CAE, 0x124D7B, 0x124DCA, 0x124E6B,
                                0x124E9A, 0x124F3C, 0x124F6B, 0x12500D,
                                0x12503C, 0x15F5C6

                            } },
                            { AdditionalRuntime::ImportType::INTERNAL, {

                                0x125F7C, 0x7A2A5, 0x7FB98, 0x28158,
                                0x1C05C4

                            } }
                          }
                        },

                        { "Sleep",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x116115, 0x125D5C, 0x15F64A, 0x11606A } } }
                        },

                        { "SetCurrentDirectoryW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13EC29, 0x15F896 } } }
                        },

                        { "CreateEventW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13DAA8, 0x15F88A } } }
                        },

                        { "GetCurrentProcessId",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x10E54D, 0x15F3B2, 0x15F5EA } } }
                        },

                        { "OpenProcess",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x10E564, 0x15F5F0 } } }
                        },

                        { "Module32Next",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F5BA } } }
                        },

                        { "CreateHardLinkW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13EC60, 0x15F938 } } }
                        },

                        { "TerminateProcess",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x10E573, 0x157FD1, 0x15F5F6 } } }
                        },

                        { "SetFileTime",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13EA17, 0x15F902 } } }
                        },

                        { "GetModuleHandleA",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x1160FA, 0x1173D0, 0x1175D8, 0x10E5D4,
                                0x11760D, 0x11F07A, 0x11F282, 0x11F2B7,
                                0x13275A, 0x132A8F, 0x15F656

                            } },
                            { AdditionalRuntime::ImportType::INTERNAL, {

                                0x116106

                            } }
                          },
                        },

                        { "QueryPerformanceCounter",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F3BF, 0x15F986 } } }
                        },

                        { "IsDebuggerPresent",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x1579AD, 0x15F962 } } }
                        },

                        { "DeleteFileW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13EDE1, 0x15F8AE } } }
                        },

                        { "VirtualAlloc",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x1241EA, 0x1244EA, 0x12475A, 0x124BE6,
                                0x124D02, 0x124E17, 0x124EE8, 0x124FB9,
                                0x15F662

                            } }
                          },
                        },

                        { "WaitForSingleObjectEx",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13D9F7, 0x15F884 } } }
                        },

                        { "SetFileAttributesW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13EB52, 0x15F8F6 } } }
                        },

                        { "SetEvent",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13DA29, 0x15F878 } } }
                        },

                        { "FormatMessageA",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x14B0CB, 0x15F95C } } }
                        },

                        { "GetDiskFreeSpaceExW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13F368, 0x15F8C6 } } }
                        },

                        { "ResetEvent",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13DA35, 0x15F87E } } }
                        },

                        { "GetCurrentThreadId",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F3A9, 0x15F98C } } }
                        },

                        { "RemoveDirectoryW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13EDB9, 0x15F8EA } } }
                        },

                        { "AreFileApisANSI",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13E80F, 0x15F90E } } }
                        },

                        { "InitializeCriticalSectionAndSpinCount",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13DA49, 0x15F86C } } }
                        },

                        { "FindClose",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13E484, 0x13E78A, 0x15F8B4 } } }
                        },

                        { "GetModuleHandleW",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x13DA54, 0x13DA65, 0x13E25F, 0x13F127,
                                0x13F273, 0x13F38D, 0x157881, 0x15F890

                            } }
                          },
                        },

                        { "SetFilePointerEx",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13EF1C, 0x15F8FC } } }
                        },

                        { "GetTempPathW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13EB8C, 0x15F908 } } }
                        },

                        { "GetFullPathNameW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13E10E, 0x15F8DE } } }
                        },

                        { "SetEndOfFile",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13EF27, 0x15F8F0 } } }
                        },

                        { "GetLastError",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x13E11A, 0x13E151, 0x13E1EC, 0x13E20B,
                                0x13E2A7, 0x13E339, 0x13E377, 0x13E441,
                                0x13E468, 0x13E55D, 0x13E63B, 0x13E7F3,
                                0x13E83C, 0x13E8BD, 0x13E8ED, 0x13E981,
                                0x13E9C0, 0x13EA21, 0x13EA74, 0x13EB32,
                                0x13EB9A, 0x13EC14, 0x13EC33, 0x13EC6E,
                                0x13ECB1, 0x13ED30, 0x13EDD1, 0x13EDEB,
                                0x13EDF5, 0x13EE63, 0x13EE99, 0x13EEDA,
                                0x13EF3B, 0x13EF91, 0x13F176, 0x13F1A6,
                                0x13F212, 0x13F247, 0x13F30B, 0x13F32F,
                                0x13F377, 0x13F42A, 0x14B0AD, 0x15F914

                            } }
                          }
                        },

                        { "CreateFileW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13E141, 0x13E32C, 0x13E36A, 0x15F8A8 } } }
                        },

                        { "GetFileInformationByHandle",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x13E1FC, 0x13E717, 0x13E998, 0x13F31B,
                                0x15F8D8

                            } }
                          }
                        },

                        { "FindFirstFileExW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13E434, 0x13E45B, 0x13E77A, 0x15F8BA } } }
                        },

                        { "GetFileAttributesExW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13E553, 0x15F8D2 } } }
                        },

                        { "FindNextFileW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13E7E5, 0x15F8C0 } } }
                        },

                        { "GetVolumePathNameW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13F352, 0x15F8E4 } } }
                        },

                        { "MultiByteToWideChar",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13E830, 0x15F93E } } }
                        },

                        { "WideCharToMultiByte",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13E885, 0x13E8B1, 0x13E8E1, 0x15F944 } } }
                        },

                        { "DeviceIoControl",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13ECA7, 0x15F920 } } }
                        },

                        { "GetCurrentDirectoryW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13EBFF, 0x15F89C } } }
                        },

                        { "CreateToolhelp32Snapshot",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F5AE } } }
                        },

                        { "CreateDirectoryW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13ED1D, 0x15F8A2 } } }
                        },

                        { "MoveFileExW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13EECC, 0x15F932 } } }
                        },

                        { "SetLastError",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x13F088, 0x13F095, 0x13F151, 0x13F15E,
                                0x15F91A

                            } }
                          }
                        },

                        { "CopyFileW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13F190, 0x15F92C } } }
                        },

                        { "Module32First",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F5B4 } } }
                        },

                        { "CreateDirectoryExW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13F418, 0x15F926 } } }
                        },

                        { "FreeLibrary",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x14AF64, 0x15F94A } } }
                        },

                        { "LoadLibraryExA",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x14AF79, 0x14B270, 0x15F956 } } }
                        },

                        { "GetStartupInfoW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x157868, 0x15F974 } } }
                        },

                        { "SetUnhandledExceptionFilter",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x1578CF, 0x1579CD, 0x157FB6, 0x15F96E

                            } }
                          }
                        },

                        { "UnhandledExceptionFilter",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x1579D7, 0x157FBF, 0x15F968 } } }
                        },

                        { "GetCurrentProcess",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x157FCA, 0x15F980 } } }
                        },

                        { "GetSystemTimeAsFileTime",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F39A, 0x15F992 } } }
                        },

                        { "Process32First",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F5DE } } }
                        },

                        { "Process32Next",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F5E4 } } }
                        },

                        { "IsProcessorFeaturePresent",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F97A } } }
                        }

                }

        },


        //MSVCP140.
        { "msvcp140",

                {

                        { "?_Xlength_error@std@@YAXPBD@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6E6 } } }
                        },

                        { "?tellg@?$basic_istream@DU?$char_traits@D@std@@@std@@QAE?AV?$fpos@U_Mbstatet@@@2@XZ",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x1E9F, 0x2558C, 0x3C89C, 0x15F824

                            } }
                          }
                        },

                        { "?_Winerror_map@std@@YAHH@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6CE } } }
                        },

                        { "?_Getcvt@_Locinfo@std@@QBE?AU_Cvtvec@@XZ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x9A044, 0x9A1B4, 0x15F7C4 } } }
                        },

                        { "?seekg@?$basic_istream@DU?$char_traits@D@std@@@std@@QAEAAV12@_JH@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x1EB5, 0x15F80C } } }
                        },

                        { "??1ios_base@std@@UAE@XZ",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x1FAB,   0x3092,   0x30B6,   0x30EA,
                                0x255D9,  0x31248,  0x31390,  0x3151D,
                                0x31862,  0x3188A,  0x3C51C,  0x3C8E9,
                                0x3DE4A,  0x5F903,  0x62CD3,  0x691F3,
                                0x69AF7,  0x6A5BA,  0x6BFF4,  0x10FAF2,
                                0x1106EB, 0x1333C2, 0x15F7A6

                            } }
                          }
                        },

                        { "_Cnd_do_broadcast_at_thread_exit",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F72E } } }
                        },

                        { "??0?$basic_streambuf@DU?$char_traits@D@std@@@std@@IAE@XZ",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x2AE2,  0x31774, 0x5F86E, 0x62C3E,
                                0x6997F, 0x6A4EF, 0x6BF1F, 0x15F788
                            } }
                          },
                        },

                        { "??7ios_base@std@@QBE_NXZ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x1F25, 0x15F7E2 } } }
                        },

                        { "?_Execute_once@std@@YAHAAUonce_flag@1@P6GHPAX1PAPAX@Z1@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F69E } } }
                        },

                        { "?_Throw_C_error@std@@YAXH@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6BC } } }
                        },

                        { "?read@?$basic_istream@DU?$char_traits@D@std@@@std@@QAEAAV12@PAD_J@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x1F18, 0x15F800 } } }
                        },

                        { "??0ios_base@std@@IAE@XZ",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x2A6A,  0x3170A, 0x5F7ED, 0x62BBD,
                                0x698FB, 0x6A46E, 0x6BE9E, 0x15F794

                            } }
                          },
                        },

                        { "_Cnd_destroy_in_situ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F728 } } }
                        },

                        { "?init@?$basic_ios@DU?$char_traits@D@std@@@std@@IAEXPAV?$basic_streambuf@DU?$char_traits@D@std@@@2@_N@Z",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x2AC2,  0x31754, 0x5F849, 0x62C19,
                                0x6995A, 0x6A4CA, 0x6BEFA, 0x15F7FA

                            } }
                          },
                        },

                        { "?sbumpc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x3EC06, 0x15F806 } } }
                        },

                        { "?clear@?$basic_ios@DU?$char_traits@D@std@@@std@@QAEXH_N@Z",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x2B8B,   0x316DD, 0x3181D, 0x3C4AC,
                                0x3DF1D,  0x3EC39, 0x6A3C8, 0x6A749,
                                0x15F7D6

                            } }
                          },
                        },

                        { "?getloc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QBE?AVlocale@2@XZ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x2FBE, 0x15F7EE } } }
                        },

                        { "?showmanyc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MAE_JXZ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6FE } } }
                        },

                        { "?xsputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MAE_JPBD_J@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x372A, 0x15F71C } } }
                        },

                        { "?xsgetn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MAE_JPAD_J@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x363A, 0x15F716 } } }
                        },

                        { "??1?$basic_streambuf@DU?$char_traits@D@std@@@std@@UAE@XZ",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x3C8C,   0x5F8FB, 0x62CCB, 0x691E8,
                                0x69223,  0x69AEA, 0x6A5B2, 0x6BFEC,
                                0x15F79A

                            } }
                          },
                        },

                        { "_Mtx_unlock",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F764 } } }
                        },

                        { "_Cnd_init_in_situ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F734 } } }
                        },

                        { "?_Xout_of_range@std@@YAXPBD@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6EC } } }
                        },

                        { "??0_Lockit@std@@QAE@H@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x3EB1, 0x3ED0, 0x15F78E } } }
                        },

                        { "_Mtx_current_owns",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F74C } } }
                        },

                        { "??1_Lockit@std@@QAE@XZ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x3EEA, 0x3F57, 0x15F7A0 } } }
                        },

                        { "?_Getcat@?$codecvt@DDU_Mbstatet@@@std@@SAIPAPBVfacet@locale@2@PBV42@@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x3F2A, 0x15F7BE } } }
                        },

                        { "?_Assign@_ContextCallback@details@Concurrency@@AAEXPAX@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6F2 } } }
                        },

                        { "?_Getgloballocale@locale@std@@CAPAV_Locimp@12@XZ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6AA } } }
                        },

                        { "?good@ios_base@std@@QBE_NXZ",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x2557B,  0x3C88B,  0x3C9F1,  0x6A2D2,
                                0x6A303,  0x6A5F4,  0x6A622,  0x10F54F,
                                0x10F57B, 0x10F93F, 0x1105FF, 0x15F7F4

                            } }
                          },
                        },

                        { "?good@ios_base@std@@QBE_NXZ",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x2557B,  0x3C88B,  0x3C9F1,  0x6A2D2,
                                0x6A303,  0x6A5F4,  0x6A622,  0x10F54F,
                                0x10F57B, 0x10F93F, 0x1105FF, 0x15F7F4

                            } }
                          },
                        },

                        { "?ReportUnhandledError@_ExceptionHolder@details@Concurrency@@AAEXXZ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6B0, 0x15F6C8 } } }
                        },

                        { "?write@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV12@PBD_J@Z",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x31210, 0x31358,  0x314E5,  0x3C4D5,
                                0x6985B, 0x6987E,  0x69B59,  0x6A542,
                                0x6BF7C, 0x15F830, 0x11062D

                            } }
                          },
                        },

                        { "?widen@?$basic_ios@DU?$char_traits@D@std@@@std@@QBEDD@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x3CA0C, 0x10F59D, 0x15F82A } } }
                        },

                        { "?_Ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QAE_N_N@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x3EB27, 0x15F7CA } } }
                        },

                        { "?sgetc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x3EB5F, 0x15F812 } } }
                        },

                        { "?copyfmt@ios_base@std@@QAEAAV12@ABV12@@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x699CA, 0x15F7DC } } }
                        },

                        { "?copyfmt@ios_base@std@@QAEAAV12@ABV12@@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x6A2F6, 0x6A615, 0x15F7E8 } } }
                        },

                        { "?setbuf@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MAEPAV12@PAD_J@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6F8 } } }
                        },

                        { "?_Throw_Cpp_error@std@@YAXH@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6C2 } } }
                        },

                        { "?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHD@Z",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x6A38F,  0x6A68F, 0x6A6C7, 0x6A6FF,
                                0x15F81E

                            } },
                            { AdditionalRuntime::ImportType::INTERNAL, {

                                0x6A32A

                            } }
                          },
                        },

                        { "?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEXXZ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x6A3D9, 0x6A75A, 0x15F7D0 } } }
                        },

                        { "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV01@H@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x6A437, 0x6A514, 0x15F7B2 } } }
                        },

                        { "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV01@M@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x6BE65, 0x6BF4E, 0x15F7B8 } } }
                        },

                        { "??4?$_Yarn@G@std@@QAEAAV01@PBG@Z",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x9A095,  0x9A0FA, 0x9A205, 0x9A26A,
                                0x15F7AC

                            } }
                          },
                        },

                        { "?_Fiopen@std@@YAPAU_iobuf@@PBDHH@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6A4 } } }
                        },

                        { "?_Syserror_map@std@@YAPBDH@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6B6 } } }
                        },

                        { "?_Winerror_message@std@@YAKKPADK@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6D4 } } }
                        },

                        { "?_Xbad_alloc@std@@YAXXZ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6DA } } }
                        },

                        { "_Cnd_broadcast",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F722 } } }
                        },

                        { "?_Xinvalid_argument@std@@YAXPBD@Z",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F6E0 } } }
                        },

                        { "?do_encoding@?$codecvt@_SDU_Mbstatet@@@std@@MBEHXZ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F704 } } }
                        },

                        { "?uflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MAEHXZ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F70A } } }
                        },

                        { "?uncaught_exception@std@@YA_NXZ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F710 } } }
                        },

                        { "_Cnd_signal",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F73A } } }
                        },

                        { "_Cnd_timedwait",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F740 } } }
                        },

                        { "_Cnd_wait",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F746 } } }
                        },

                        { "_Mtx_destroy_in_situ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F752 } } }
                        },

                        { "_Mtx_init_in_situ",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F758 } } }
                        },

                        { "_Mtx_lock",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F75E } } }
                        },

                        { "_Query_perf_counter",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F76A } } }
                        },

                        { "_Query_perf_frequency",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F770 } } }
                        },

                        { "_Thrd_detach",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F776 } } }
                        },

                        { "_Thrd_hardware_concurrency",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F77C } } }
                        },

                        { "_Xtime_get_ticks",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F782 } } }
                        },

                        { "?snextc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC,   { 0x15F818 } },
                            { AdditionalRuntime::ImportType::INTERNAL, { 0x3EB74, 0x3EBB9 } }
                          }
                        },

                        { "?id@?$codecvt@DDU_Mbstatet@@@std@@2V0locale@2@A",
                          { { AdditionalRuntime::ImportType::INTERNAL, { 0x3EB9 } } }
                        },

                        { "?write@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QAEAAV12@PB_W_J@Z",
                          { { AdditionalRuntime::ImportType::INTERNAL, { 0x69B13 } } }
                        },

                        { "?_Id_cnt@id@locale@std@@0HA",
                          { { AdditionalRuntime::ImportType::INTERNAL, { 0x1C067C } } }
                        }

                }

        },

        //VCRUNTIME140.
        { "vcruntime140",

          {

                { "_CxxThrowException",
                  {
                    { AdditionalRuntime::ImportType::PUBLIC, {

                        0x20B4,  0x3F94,  0x95B2E, 0x96808,
                        0x97B48, 0x97CA8, 0x97E08, 0x97F68,
                        0x980C8, 0x98228, 0x9ABB5, 0x9C1B4,
                        0x9CE4C, 0x9CF4C, 0x9CF9F, 0x9DDDA,
                        0xB2504, 0x15F99E

                    } }
                  }
                },

                { "__std_exception_copy",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9B6 } } }
                },

                { "__current_exception",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9AA } } }
                },

                { "__std_exception_destroy",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9BC } } }
                },

                { "memmove",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9F8 } } }
                },

                { "__CxxFrameHandler",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9A4 } } }
                },

                { "__current_exception_context",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9B0 } } }
                },

                { "__std_type_info_destroy_list",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9C8 } } }
                },

                { "memcpy",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9F2 } } }
                },

                { "__std_terminate",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9C2 } } }
                },

                { "_except_handler4_common",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9CE } } }
                },

                { "_purecall",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9D4 } } }
                },

                { "_setjmp3",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9DA } } }
                },

                { "longjmp",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9E0 } } }
                },

                { "memchr",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9E6 } } }
                },

                { "memcmp",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9EC } } }
                },

                { "memset",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F9FE } } }
                },

                { "strchr",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA04 } } }
                },

                { "strrchr",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA0A } } }
                },

                { "strstr",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA10 } } }
                }

          }

        },


        //NTDLL.
        { "ntdll",

          {

                { "RtlEnterCriticalSection",
                  {
                    { AdditionalRuntime::ImportType::PUBLIC, {

                        0x13D8EC, 0x13D93D, 0x13D961, 0x13D9A6,
                        0x13D9FE, 0x15F860

                    } }
                  }
                },

                { "RtlLeaveCriticalSection",
                  {
                    { AdditionalRuntime::ImportType::PUBLIC, {

                        0x13D929, 0x13D94A, 0x13D994, 0x13D9B2,
                        0x13D9E6, 0x15F866

                    } }
                  }
                },

                { "RtlInitializeSListHead",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F3DA, 0x15F998 } } }
                },

                { "RtlDeleteCriticalSection",
                  { { AdditionalRuntime::ImportType::PUBLIC, { 0x13DAC4, 0x15F872 } } }
                }

          }

        },

        //UCRTBASE.
        { "ucrtbase",

                {

                        { "fgetpos",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x388A, 0x15FAFA } } }
                        },

                        { "fputc",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x325F, 0x327D, 0x15FB00 } } }
                        },

                        { "calloc",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x9A0C1, 0x9A126, 0x9A14C,  0x9A231,
                                0x9A296, 0x9A2BC, 0x15FAE2

                            } }
                          }
                        },

                        { "_invalid_parameter_noinfo_noreturn",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x1fc3,   0x2027,   0x2087,   0x26f0,
                                0x27f5,   0x2a44,   0x2c32,   0x2d5a,
                                0x2eb5,   0x35fe,   0x3e8d,   0x612b,
                                0x704c,   0x7a99,   0x8ce4,   0x9893,
                                0x9dbf,   0xa086,   0xa3d5,   0xa8bb,
                                0xa9c1,   0xb19b,   0xb2b0,   0xb3ea,
                                0xba6a,   0xbb27,   0xbba0,   0xc080,
                                0xc0fa,   0xc1ac,   0xc261,   0xc320,
                                0xc41e,   0x12067,  0x13bc0,  0x15673,
                                0x158e5,  0x15b3d,  0x15bd0,  0x15c70,
                                0x15dca,  0x15e1d,  0x161de,  0x19ac9,
                                0x19c70,  0x19ffd,  0x1a093,  0x1a1c0,
                                0x1a227,  0x1e4d4,  0x1eb93,  0x1ec97,
                                0x1ecf7,  0x1ed90,  0x1ee2a,  0x211c3,
                                0x212d7,  0x21dad,  0x21e4d,  0x21feb,
                                0x2219b,  0x22733,  0x25228,  0x25dc7,
                                0x261c7,  0x26253,  0x26380,  0x26577,
                                0x265d7,  0x26ac2,  0x27623,  0x27a83,
                                0x27d9b,  0x2822d,  0x2c36f,  0x2c483,
                                0x2c4e7,  0x2c61a,  0x2c6d0,  0x2d2f5,
                                0x2dcd6,  0x2e9c3,  0x2eb77,  0x2ed3d,
                                0x2edc2,  0x2ee6d,  0x2ef10,  0x2f00f,
                                0x2f250,  0x2f30d,  0x2f58b,  0x2f617,
                                0x2f677,  0x2f6d7,  0x310a4,  0x3160b,
                                0x31969,  0x31efb,  0x320aa,  0x32629,
                                0x330de,  0x33cc8,  0x34c68,  0x36cea,
                                0x3711e,  0x384d3,  0x38a03,  0x39240,
                                0x3991d,  0x399cd,  0x39a9b,  0x39b50,
                                0x39d20,  0x3ad8d,  0x3c564,  0x3de58,
                                0x3e164,  0x3e4a8,  0x3e648,  0x3e7b4,
                                0x3e82a,  0x3e8eb,  0x3eafa,  0x3f5fa,
                                0x3fa83,  0x3fb20,  0x41843,  0x41990,
                                0x42513,  0x42597,  0x42620,  0x42c8e,
                                0x430b7,  0x432f0,  0x43852,  0x438c7,
                                0x43927,  0x43997,  0x439f7,  0x43a67,
                                0x43ac7,  0x44797,  0x44c99,  0x44dd3,
                                0x45bbb,  0x45e7f,  0x4690f,  0x469b0,
                                0x477d6,  0x47ad4,  0x47c13,  0x47f57,
                                0x49483,  0x4e285,  0x4e5f5,  0x4fa28,
                                0x4fd6b,  0x4fee3,  0x4ff70,  0x5036a,
                                0x5069d,  0x50786,  0x5086c,  0x50954,
                                0x50aa9,  0x50dfd,  0x50edf,  0x50fcd,
                                0x51087,  0x51493,  0x52259,  0x54576,
                                0x54603,  0x54941,  0x54a50,  0x54b81,
                                0x54cb0,  0x55012,  0x55af6,  0x55ebe,
                                0x56538,  0x5674e,  0x56867,  0x5699a,
                                0x57423,  0x579b7,  0x57d8d,  0x58623,
                                0x59e52,  0x5b866,  0x5e5b3,  0x6475f,
                                0x653cd,  0x68c63,  0x68fc7,  0x693b8,
                                0x697c4,  0x69bb0,  0x6a5c8,  0x6a961,
                                0x6ae7e,  0x6b0bb,  0x6b160,  0x6b1c7,
                                0x6b5fb,  0x6b697,  0x6b83b,  0x6bc78,
                                0x6c002,  0x6c207,  0x6f593,  0x6f630,
                                0x6fb76,  0x752a0,  0x75481,  0x7551b,
                                0x761b1,  0x762b8,  0x76c81,  0x78a01,
                                0x78a87,  0x78c87,  0x78ceb,  0x78d8d,
                                0x792f2,  0x795c3,  0x79864,  0x79baa,
                                0x79e8b,  0x7a23d,  0x7c161,  0x7c213,
                                0x7c2a7,  0x7c330,  0x7c397,  0x7c552,
                                0x7d43c,  0x7d579,  0x7d620,  0x7d687,
                                0x7db6f,  0x7dbf7,  0x7e1ad,  0x7e243,
                                0x7e7d3,  0x7f568,  0x7f82a,  0x7f8b3,
                                0x7f9b7,  0x7fa17,  0x7fac0,  0x7fb3a,
                                0x7ffef,  0x80253,  0x8047f,  0x80770,
                                0x80a93,  0x81401,  0x81f48,  0x822f3,
                                0x82973,  0x829e7,  0x82b47,  0x82db6,
                                0x83453,  0x83688,  0x84b77,  0x84f70,
                                0x85550,  0x85613,  0x85677,  0x8596d,
                                0x85f63,  0x86676,  0x86703,  0x86790,
                                0x86eab,  0x8733b,  0x87b3b,  0x87e8d,
                                0x880d0,  0x8822d,  0x88470,  0x890e5,
                                0x89e28,  0x8ace2,  0x8bae8,  0x8c8fc,
                                0x8d772,  0x8dcef,  0x8dfcb,  0x8e58d,
                                0x8f15c,  0x90082,  0x90677,  0x90910,
                                0x9871d,  0x98e62,  0x99ecc,  0x9ab77,
                                0x9af38,  0x9b0a0,  0x9b45b,  0x9b566,
                                0x9b887,  0x9bbab,  0x9bd60,  0x9bf08,
                                0x9c15b,  0x9c310,  0x9cb29,  0x9cb8c,
                                0x9cd4c,  0x9cf12,  0x9d14c,  0x9d64e,
                                0x9e9dc,  0xa0bd5,  0xa4258,  0xa471e,
                                0xa484f,  0xa4907,  0xa93f6,  0xa957a,
                                0xaa0bd,  0xaa277,  0xaa8f7,  0xaabfa,
                                0xabce3,  0xabe68,  0xad30c,  0xad3b0,
                                0xad50a,  0xae466,  0xae6cc,  0xaea1e,
                                0xb1fad,  0xb2070,  0xb23c3,  0xb24ce,
                                0xb27c5,  0xb40fb,  0xb536b,  0xb592e,
                                0xb5df8,  0xb5e98,  0xb62b8,  0xb63ca,
                                0xb6f02,  0xb87c5,  0xb9bbc,  0xb9c81,
                                0xba125,  0xba206,  0xba2d9,  0xba9ce,
                                0xbab2e,  0xbada9,  0xbbd0d,  0xbc9f1,
                                0xbd0d5,  0xc013d,  0xc01da,  0xc08a7,
                                0xc1027,  0xc1d74,  0xc24c6,  0xc26b4,
                                0xc38b0,  0xc3c03,  0xc3c94,  0xc3f5c,
                                0xc51f0,  0xc5543,  0xc55fd,  0xc57a8,
                                0xc59fd,  0xc5b62,  0xc69f0,  0xc9250,
                                0xc95a3,  0xc968c,  0xc9701,  0xc9e88,
                                0xca314,  0xca6d5,  0xcab23,  0x109e8f,
                                0x109e95, 0x109e9b, 0x109ea1, 0x109ea7,
                                0x10d59d, 0x10d7aa, 0x10d81b, 0x10d8a1,
                                0x10dd4f, 0x10deca, 0x10e37d, 0x10e5e5,
                                0x10e697, 0x10fb3b, 0x11076b, 0x1109ac,
                                0x112596, 0x1128f5, 0x11366a, 0x113712,
                                0x115af0, 0x115bac, 0x115c98, 0x115ec7,
                                0x115fe9, 0x1189c5, 0x11e1b1, 0x11f4c1,
                                0x1230bb, 0x1251e0, 0x12548e, 0x12605a,
                                0x1260da, 0x12615a, 0x1261da, 0x12625a,
                                0x1262da, 0x12635a, 0x1263da, 0x12645a,
                                0x1264da, 0x12655a, 0x1265da, 0x12665a,
                                0x126834, 0x1268ba, 0x12693a, 0x1269ba,
                                0x126a3a, 0x126b52, 0x126d44, 0x126f34,
                                0x126fba, 0x1270d2, 0x1272c4, 0x1273e2,
                                0x12746a, 0x127654, 0x127844, 0x12796c,
                                0x127e63, 0x127efa, 0x127f61, 0x127fc7,
                                0x1282be, 0x12ab11, 0x12acd7, 0x12bce5,
                                0x12c8a7, 0x12c907, 0x12c967, 0x12c9c7,
                                0x12ca27, 0x12d6e7, 0x12f6f8, 0x12f8cc,
                                0x12f9e1, 0x12fb2d, 0x12fbd2, 0x12fd82,
                                0x131424, 0x1321ed, 0x13238b, 0x13247c,
                                0x132a78, 0x133222, 0x133448, 0x13366a,
                                0x1338bd, 0x133cdc, 0x133de9, 0x13408f,
                                0x134936, 0x134bca, 0x134ce2, 0x134ef2,
                                0x135c4b, 0x135d66, 0x1361f4, 0x136465,
                                0x13669e, 0x136941, 0x136baa, 0x136dea,
                                0x136f1a, 0x138263, 0x138b53, 0x1391b0,
                                0x139423, 0x139863, 0x15fabe

                            } }
                          }
                        },

                        { "__stdio_common_vsprintf",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x3E4D5, 0xABB68, 0x1330B1, 0x1332D7,
                                0x15FA40

                            } }
                          }
                        },

                        { "_atoi64",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x3CB74, 0x3CBB9, 0x98E89, 0x15FADC } } }
                        },

                        { "_get_stream_buffer_pointers",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x2F7C, 0x3AC4, 0x15FAB8 } } }
                        },

                        { "_lock_file",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x314B, 0x15FAC4 } } }
                        },

                        { "atoi",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FAD6 } } }
                        },

                        { "atol",
                          { { AdditionalRuntime::ImportType::INTERNAL, { 0x3D384 } } }
                        },

                        { "__stdio_common_vswprintf",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x90175, 0x15FAA6 } } }
                        },

                        { "_unlock_file",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x316B, 0x15FACA } } }
                        },

                        { "fgetc",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x33F8, 0x34F8, 0x3537, 0x15FAF4

                            } }
                          }
                        },

                        { "fwrite",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x322A, 0x37DB, 0x3D1F, 0x15FB18

                            } }
                          }
                        },

                        { "ungetc",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x332A, 0x358C, 0x15FB5A

                            } },

                            { AdditionalRuntime::ImportType::INTERNAL, {

                                0x359B

                            } }
                          }
                        },

                        { "_CIcosh",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA1C } } }
                        },

                        { "fsetpos",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x3965, 0x15FB12 } } }
                        },

                        { "abort",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBE4 } } }
                        },

                        { "atof",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x3D40E, 0x15FAD0 } } }
                        },

                        { "_fseeki64",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x3875, 0x15FA7C } } }
                        },

                        { "fread",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x36C3, 0x36E4, 0x15FB06 } } }
                        },

                        { "setvbuf",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x3A34, 0x15FB2A } } }
                        },

                        { "fflush",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x3B3B, 0x15FAEE } } }
                        },

                        { "_cexit",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA4C } } }
                        },

                        { "fclose",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x3C0A, 0x3163D, 0x3DE7D, 0x15FAE8

                            } }
                          }
                        },

                        { "strcat_s",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x12C495, 0x12C4A9, 0x15FB30 } } }
                        },

                        { "rand",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x1AA9D, 0x3AB3F,  0x3DB96, 0x516B8,
                                0x53E36, 0x53FF0,  0x8308F, 0x830A3,
                                0x83127, 0x83144,  0x831BC, 0x831E6,
                                0x832AF, 0x832C3,  0x8333B, 0x833AB,
                                0x89A46, 0x8A89F,  0x8B706, 0x8C514,
                                0x8D334, 0x98908,  0x99D20, 0xB5662,
                                0xB577A, 0x15FB24

                            } }
                          },
                        },

                        { "_fdtest",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x1F7E1, 0x1F86F,  0x1FBCC, 0x20221,
                                0x20809, 0x20830,  0x2084B, 0x20D46,
                                0x20D5F, 0x20D7B,  0x20DA2, 0x6E513,
                                0x6E528, 0x6E53D,  0x6E556, 0x6E56F,
                                0x6E588, 0x15FAB2

                            } },

                            { AdditionalRuntime::ImportType::INTERNAL, {

                                0x20914, 0x20DC4

                            } }
                          },
                        },

                        { "_configure_narrow_argv",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA52 } } }
                        },

                        { "__stdio_common_vsprintf_s",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x3E515, 0xBC954, 0x15FAA0 } } }
                        },

                        { "toupper",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FD16 } } }
                        },

                        { "strtoul",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x7E927,  0x1163C7, 0x1178F7, 0x117B47,
                                0x117D97, 0x118227, 0x1184F7, 0x1328C7,
                                0x15FB48

                            } }
                          },
                        },

                        { "_crt_at_quick_exit",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA58 } } }
                        },

                        { "strcpy_s",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x125EEC, 0x125F06, 0x125F9D, 0x12C482,
                                0x15FB36

                            } }
                          }
                        },

                        { "_gmtime64",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA88 } } }
                        },

                        { "tolower",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x86954, 0xB84F4, 0x15FB54

                            } },

                            { AdditionalRuntime::ImportType::INTERNAL, {

                                0x88593, 0x88680,  0x88970, 0x88CA0, 0x88EA3,
                                0x88F90, 0x891F3,  0x892E0, 0x895E0, 0x89910,
                                0x89FF3, 0x8A0E0,  0x8A3E0, 0x8A710, 0x8AEB3,
                                0x8AFA0, 0x8B2A0,  0x8B5D0, 0x8BCB3, 0x8BDA0,
                                0x8C0A0, 0x8C3D0,  0x8CAD3, 0x8CBBF, 0x8CEBF,
                                0x8D1EF, 0x10E4CD, 0x8888F, 0x88BAF, 0x894F3,
                                0x89823, 0x8A2F3,  0x8A623, 0x8B1B3, 0x8B4E3,
                                0x8BFB3, 0x8C2E3,  0x8CDD3, 0x8D103, 0xB9A79,
                                0x25F0

                            } }
                          }
                        },

                        { "wcslen",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x90125, 0x902D9, 0x15FB60 } } }
                        },

                        { "_execute_onexit_table",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA76 } } }
                        },

                        { "terminate",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x99EDD, 0x9AB71,  0x9ADCB,  0x9B2DF,
                                0x9CE8F, 0x13E176, 0x13E48E, 0x15FB4E

                            } }
                          },
                        },

                        { "_W_Getdays",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x9A085, 0x9A1F5, 0x15FA8E } } }
                        },

                        { "free",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x9A09C,  0x9A101,  0x9A20C,  0x9A271,
                                0x13F007, 0x13F014, 0x13F3C8, 0x13F3D9,
                                0x13F44D, 0x15FB0C

                            } }
                          },
                        },

                        { "_crt_atexit",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA5E } } }
                        },

                        { "_CItanh",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA2E } } }
                        },

                        { "_W_Getmonths",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x9A0E7, 0x9A257, 0x15FA94 } } }
                        },

                        { "_except1",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA70 } } }
                        },

                        { "_beginthreadex",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x15FAAC

                            } },

                            { AdditionalRuntime::ImportType::INTERNAL, {

                                0x45DEA

                            } }
                          }
                        },

                        { "_errno",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x10F7CC, 0x10F870, 0x15FA6A } } }
                        },

                        { "_strtoi64",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x10F7F1, 0x15FB42 } } }
                        },

                        { "strtod",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x10F88F, 0x15FB3C } } }
                        },

                        { "malloc",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x125F42, 0x13EFD2, 0x15FB1E } } }
                        },

                        { "_initialize_onexit_table",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FB6C } } }
                        },

                        { "___lc_codepage_func",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x13E7FD, 0x15FA9A } } }
                        },

                        { "_CIatan2",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA16 } } }
                        },

                        { "_CIfmod",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA22 } } }
                        },

                        { "_libm_sse2_asin_precise",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FB84 } } }
                        },

                        { "_CIsinh",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA28 } } }
                        },

                        { "__acrt_iob_func",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA34 } } }
                        },

                        { "__stdio_common_vfprintf",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA3A } } }
                        },

                        { "_callnewh",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA46 } } }
                        },

                        { "_difftime64",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA64 } } }
                        },

                        { "_ftelli64",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FA82 } } }
                        },

                        { "_initialize_narrow_environment",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FB66 } } }
                        },

                        { "_initterm",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FB72 } } }
                        },

                        { "_initterm_e",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FB78 } } }
                        },

                        { "_libm_sse2_acos_precise",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FB7E } } }
                        },

                        { "_libm_sse2_cos_precise",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FB8A } } }
                        },

                        { "_libm_sse2_exp_precise",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FB90 } } }
                        },

                        { "_libm_sse2_log10_precise",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FB96 } } }
                        },

                        { "_libm_sse2_log_precise",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FB9C } } }
                        },

                        { "_libm_sse2_pow_precise",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBA2 } } }
                        },

                        { "_libm_sse2_sin_precise",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBA8 } } }
                        },

                        { "_libm_sse2_sqrt_precise",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBAE } } }
                        },

                        { "_libm_sse2_tan_precise",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBB4 } } }
                        },

                        { "strncmp",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCF2 } } }
                        },

                        { "_localtime64",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBBA } } }
                        },

                        { "_mktime64",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBC0 } } }
                        },

                        { "_pclose",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBC6 } } }
                        },

                        { "_popen",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBCC } } }
                        },

                        { "_register_onexit_function",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBD2 } } }
                        },

                        { "strcoll",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCDA } } }
                        },

                        { "_seh_filter_dll",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBD8 } } }
                        },

                        { "setlocale",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCBC } } }
                        },

                        { "_time64",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBDE } } }
                        },

                        { "acos",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBEA } } }
                        },

                        { "asin",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBF0 } } }
                        },

                        { "atan",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBF6 } } }
                        },

                        { "isgraph",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC6E } } }
                        },

                        { "atan2",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FBFC } } }
                        },

                        { "ceil",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC02 } } }
                        },

                        { "clearerr",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC08 } } }
                        },

                        { "clock",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC0E } } }
                        },

                        { "system",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FD04 } } }
                        },

                        { "cos",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC14 } } }
                        },

                        { "exit",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC1A } } }
                        },

                        { "feof",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC20 } } }
                        },

                        { "floor",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC32 } } }
                        },

                        { "ferror",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC26 } } }
                        },

                        { "fgets",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC2C } } }
                        },

                        { "fopen",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC38 } } }
                        },

                        { "freopen",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC3E } } }
                        },

                        { "frexp",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC44 } } }
                        },

                        { "getc",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC4A } } }
                        },

                        { "getenv",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC50 } } }
                        },

                        { "isalnum",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC56 } } }
                        },

                        { "isalpha",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC5C } } }
                        },

                        { "iscntrl",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC62 } } }
                        },

                        { "isdigit",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC68 } } }
                        },

                        { "islower",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC74 } } }
                        },

                        { "ispunct",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC7A } } }
                        },

                        { "isspace",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC80 } } }
                        },

                        { "isupper",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC86 } } }
                        },

                        { "isxdigit",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC8C } } }
                        },

                        { "ldexp",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC92 } } }
                        },

                        { "localeconv",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC98 } } }
                        },

                        { "pow",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FC9E } } }
                        },

                        { "realloc",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCA4 } } }
                        },

                        { "remove",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCAA } } }
                        },

                        { "rename",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCB0 } } }
                        },

                        { "roundf",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCB6 } } }
                        },

                        { "sin",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCC2 } } }
                        },

                        { "sqrt",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCC8 } } }
                        },

                        { "srand",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCCE } } }
                        },

                        { "strcmp",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCD4 } } }
                        },

                        { "strerror",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCE0 } } }
                        },

                        { "strftime",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCE6 } } }
                        },

                        { "strlen",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCEC } } }
                        },

                        { "strpbrk",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCF8 } } }
                        },

                        { "strspn",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FCFE } } }
                        },

                        { "tmpfile",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FD0A } } }
                        },

                        { "tmpnam",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15FD10 } } }
                        }

                }

        },

        //USER32.
        { "user32",

                {

                        { "FlashWindowEx",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x7D81B, 0x15F5CC } } }
                        },

                        { "SetWindowLongW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x1160D4, 0x125D70, 0x15F650 } } }
                        },

                        { "CallWindowProcW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x86843, 0x15F5D2 } } }
                        },

                        { "GetDesktopWindow",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x131A20, 0x15F680 } } }
                        },

                        { "FindWindowA",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x116059, 0x15F644

                            } },

                            { AdditionalRuntime::ImportType::INTERNAL, {

                                0x116070

                            } }
                          }
                        },

                        { "GetAsyncKeyState",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x8FA86, 0x8FAD6, 0x15F5D8 } } }
                        },

                        { "GetWindowRect",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x15F67A

                            } },

                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x131A10

                            } }
                          }
                        },

                        { "GetCursorPos",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x127FDE, 0x15F668 } } }
                        },

                        { "ScreenToClient",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x127FEF, 0x15F66E } } }
                        },

                        { "GetForegroundWindow",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x131A4F, 0x15F686 } } }
                        },

                        { "GetDC",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x131A56, 0x15F68C } } }
                        },

                        { "ReleaseDC",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x131A75, 0x15F698 } } }
                        }

                }

        },

        //GDI32.
        { "gdi32",

                {

                        { "SelectObject",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x1138BC, 0x1138CA, 0x15F614

                            } },

                            { AdditionalRuntime::ImportType::INTERNAL, {

                                0x1C062C

                            } }
                          }
                        },

                        { "CreateCompatibleDC",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x113820, 0x15F5FC } } }
                        },

                        { "CreateFontA",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x1138A5, 0x15F60E } } }
                        },

                        { "SetTextColor",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x1138D9, 0x15F61A } } }
                        },

                        { "CreateDIBSection",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x113837, 0x15F602 } } }
                        },

                        { "SetMapMode",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x113858, 0x15F608 } } }
                        },

                        { "SetBkColor",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x1138E2, 0x15F620 } } }
                        },

                        { "SetTextAlign",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x1138EB, 0x15F626 } } }
                        },

                        { "GetTextExtentPoint32W",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x113904, 0x11398F, 0x15F62C } } }
                        },

                        { "ExtTextOutW",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x1139C8, 0x15F632 } } }
                        },

                        { "DeleteDC",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x113B7E, 0x15F63E } } }
                        },

                        { "AddFontMemResourceEx",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x12D0C0, 0x12D1BC, 0x12D23B, 0x12D2BA,
                                0x15F674

                            } },

                            { AdditionalRuntime::ImportType::INTERNAL, {

                                0x12D0F3

                            } }
                          }
                        },

                        { "GetPixel",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x131A6A, 0x15F692 } } }
                        },

                        { "DeleteObject",
                          {
                            { AdditionalRuntime::ImportType::PUBLIC, {

                                0x15F638

                            } },

                            { AdditionalRuntime::ImportType::INTERNAL, {

                                0x113B6F

                            } }
                          }
                        }

                }

        },

        //D3DX943.
        { "D3DX9_43",

                {

                        { "D3DXCreateSprite",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F836 } } }
                        },

                        { "D3DXMatrixMultiply",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F842 } } }
                        },

                        { "D3DXCreateTextureFromFileInMemory",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F83C } } }
                        },

                        { "D3DXMatrixRotationYawPitchRoll",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F848 } } }
                        },

                        { "D3DXMatrixScaling",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F84E } } }
                        },

                        { "D3DXMatrixTranslation",
                          { { AdditionalRuntime::ImportType::PUBLIC, { 0x15F854 } } }
                        }

                }

        }

};