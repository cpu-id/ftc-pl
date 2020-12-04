#include "FataEngine.hpp"

void FataEngine::GenerateProcessKey () {

    //Premium security bypass.

    //Remove old process id from key.
    *reinterpret_cast <int*> (Primal::AllocParameters.m_base + 0x1C31D4) ^= 0x5204;

    //Update key with new process id.
    *reinterpret_cast <int*> (Primal::AllocParameters.m_base + 0x1C31D4) ^= GetCurrentProcessId ();

}

void FataEngine::SearchOffsets () {

    //Get info about offsets. (Module & vec)
    for (const auto& offsetInfo : m_offsets) {

        //Get all offsets for module.
        for (const auto& offset : offsetInfo.second) {

            //Is offset buffer-wrap oriented?
            if (offset.m_isBufferOriented) {

                //Buffer for offset [8 bytes].
                //
                //p.s
                // Internal handler reads only last 4 bytes.
                // We can't use free for this memory, because it's storage for "InvokeEngine".
                int* buffer = static_cast <int*> (malloc (8));

                //Search offset & set data to allocated buffer. [Alloca + 0x4 = offset]
                *reinterpret_cast <int*> (buffer + 0x1) = CommonUtil::SearchSignature (offsetInfo.first, offset.m_signature);

                //Set address of new allocated buffer to old. [Override buffer]
                *reinterpret_cast <int*> (Primal::AllocParameters.m_base + offset.m_rva) = reinterpret_cast <int> (buffer);

            } else {

                //Search offset & set data to rva.
                *reinterpret_cast <int*> (Primal::AllocParameters.m_base + offset.m_rva) = CommonUtil::SearchSignature (offsetInfo.first, offset.m_signature);

            }

        }

    }

}

void FataEngine::DestroyChildProcess () {

  //TODO: Remove syscall for fork current process from segment.

  //5-sec timeout for engine init.
  Sleep (5000);

  //Target process info.
  HANDLE process;
  int processId;

  do {

    //Find second process id.
    processId = CommonUtil::GetChildProcessID ("csgo.exe");

    //1-sec search timeout.
    Sleep (1000);

  } while (processId == 0); //Do search while process id is not null.

  //Get access to process.
  process = OpenProcess (PROCESS_ALL_ACCESS, FALSE, processId);

  //Destroy child process.
  TerminateProcess (process, 1);

}