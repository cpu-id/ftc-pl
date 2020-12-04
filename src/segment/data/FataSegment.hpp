#pragma once

#include "sections/SectionAccessor.hpp"
#include "../../primal/segment/internal/SegmentProvider.hpp"

class FataSegment : public Segment {

public:

    virtual Segment::SegmentData GetSegmentData () override;

    virtual AdditionalRuntime::AllocaParameters GetAllocationParameters () override;

    virtual Segment::ReconstructProcessorDefinition GetReconstructProcessorDefinition () override;

private:

    AdditionalRuntime::RelocationDefinition m_relocationInfo = { 0xA00000, SectionAccessor::Relocations, 0x6B53 };
    std::map <std::string, std::vector <AdditionalRuntime::ImportDefinition>> m_importInfo = SectionAccessor::IAT;

};