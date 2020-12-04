#pragma once

#include "../../../Vendor.hpp"

//Bridge for section data.
namespace SectionAccessor {

    extern std::map <std::string, std::vector <AdditionalRuntime::ImportDefinition>> IAT;
    extern int Relocations [];

}