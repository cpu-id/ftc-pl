cmake_minimum_required(VERSION 3.16.5)

#From scratch to sky.
project(ftc-pl)
set(CMAKE_CXX_STANDARD 14)

#Loader.
set(

        PRIMAL_LOADER_SOURCE

        #Segment data.
        src/primal/segment/internal/SegmentNativeData.cpp

        #Runtime handler's.
        src/primal/runtime/reconstructor/Reconstructor.hpp
        src/primal/runtime/reconstructor/reconstructors/IATReconstructor.cpp
        src/primal/runtime/reconstructor/reconstructors/RelocReconstructor.cpp
        src/primal/runtime/RuntimeEngine.cpp

        #Utils.
        src/primal/util/stuff/RuntimeDefinitions.cpp
        src/primal/util/CommonUtil.cpp
        src/primal/util/PanicUtil.cpp

)

#Segment.
set(
        FATA_SEGMENT_SOURCE

        #Segment data.
        src/segment/data/sections/IAT.cpp
        src/segment/data/sections/Reloc.cpp
        src/segment/data/FataSegment.cpp

        #Boot.
        src/segment/loader/bootstrap/Bootstrap.cpp
		src/segment/loader/bootstrap/BootstrapTaskController.cpp

        #Framework routine.
		src/segment/internal/framework/FataEngine.cpp

)

#Build.
add_library(ftc-pl SHARED ${PRIMAL_LOADER_SOURCE} ${FATA_SEGMENT_SOURCE})