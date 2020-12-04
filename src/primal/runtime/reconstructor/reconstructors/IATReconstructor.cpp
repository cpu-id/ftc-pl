#include "IATReconstructor.hpp"

void IATReconstructor::ReconstructNative () {

    /**
     *
     * @point - Get additional shifting by import type. (!Segment dependency!)
     *
     * @args  - Type: Import type.
     *
     */

    auto GetAdditionalTypeRVAShift = [](AdditionalRuntime::ImportType type) {

        switch (type) {

            //Internal and etc.
            default: return 0;

            //Segment have +1 shift to all public import's.
            case AdditionalRuntime::ImportType::PUBLIC: return 1;

        }

    };

    //Get import info.
    for (const auto& importInfo : *GetImportsInfo ()) {

        //Iterate import table.
        for (const auto& iat : importInfo.second) {

            //Get target function address in application.
            int function = reinterpret_cast <int> (CommonUtil::GetOrLoadFunction (importInfo.first.c_str (), iat.m_function.c_str ()));

            //Iterate info about relocation's for function.
            for (const auto& relocationInfo : iat.m_relocations) {

                //Iterate all rva's for this ImportType of function.
                for (const auto& rva : relocationInfo.second) {

                    //Parse & set new import address.
                    *reinterpret_cast <int*> (GetAllocationParameters().m_base + rva + GetAdditionalTypeRVAShift (relocationInfo.first)) = GetImportAbsoluteAddress (relocationInfo.first, function, rva);

                }

            }

        }

    }

}

int IATReconstructor::GetImportAbsoluteAddress (AdditionalRuntime::ImportType type, int function, int rva) {

    //Parse import type.
    switch (type) {

        //JMP or CALL.
        default:
        case AdditionalRuntime::ImportType::PUBLIC: {
            return (function - rva) - GetAllocationParameters().m_base - 5;
        };

        //LEA or MOV.
        case AdditionalRuntime::ImportType::INTERNAL: {
            return function;
        };

    }

}