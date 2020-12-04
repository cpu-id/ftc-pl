#include "../../../Vendor.hpp"
#include "BootstrapTaskController.hpp"

/**
 *
 * ANOTHER PROJECTS:
 * -
 * SEGMENT BOOTSTRAP ENGINE: https://github.com/cpu-id/primal.
 *
 **/

BOOL APIENTRY DllMain (HMODULE module, DWORD callTrace, LPVOID lpReserved) {

    if (callTrace == DLL_PROCESS_ATTACH) {
		
		//New thread for avoid deadlock.

        //Init engine.
        CreateThread (NULL, NULL, BootstrapTask::InitializeEngine, NULL, NULL, NULL);

    }

    return TRUE;

}