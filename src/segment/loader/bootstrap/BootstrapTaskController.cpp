#include "BootstrapTaskController.hpp"

DWORD WINAPI BootstrapTask::InitializeEngine (_In_ LPVOID lpParameter) {

      ///////////////////////////////////////////////////////////////////////////////////////
    //                                                                                      //
    // SEGMENT ROUTINE DATA.                                                                //
    //                                                                                      //
        FataSegment segment = Singleton <FataSegment> :: GetInstance ();                    //
        SegmentInterpreter framework = Singleton <SegmentInterpreter> :: GetInstance ();    //
    //                                                                                      //
     ////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                      //
    //  RUNTIME.                                                                            //
    //                                                                                      //
        RuntimeEngine runtime (segment);                                                    //
    //                                                                                      //
     ////////////////////////////////////////////////////////////////////////////////////////

    //Alloca memory & copy segment.
    runtime.ExtractSegment ();

    //Reconstruct IAT and relocations.
    runtime.ExecuteReconstruction ();

    //Segment routine...
    framework.CallbackWithOEP (SegmentTranslator::CallbackType::BEFORE);

    //Invoke OriginalEntryPoint a.k.a DllEntryPoint.
    runtime.InvokeOEP ();

    //Segment routine...
    framework.CallbackWithOEP (SegmentTranslator::CallbackType::AFTER);

    //Complete.
    return 0;

}