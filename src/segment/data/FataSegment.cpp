#include "FataSegment.hpp"

Segment::SegmentData FataSegment::GetSegmentData () {
    return SegmentData { 0x2C6000, 0x15F2A2 };
}

AdditionalRuntime::AllocaParameters FataSegment::GetAllocationParameters () {
    return AdditionalRuntime::AllocaParameters { 0x0, 0x500000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE };
}

Segment::ReconstructProcessorDefinition FataSegment::GetReconstructProcessorDefinition () {
    return ReconstructProcessorDefinition { &m_relocationInfo, &m_importInfo };
}