#pragma once

#include "../../Vendor.hpp"
#include "framework/FataEngine.hpp"
#include "../../primal/segment/SegmentTranslator.hpp"

//SegmentInterpreter -> Internal init routine [Before/After OEP].
class SegmentInterpreter : public SegmentTranslator {

public:

	void CallbackWithOEP (CallbackType type) override {

        switch (type) {

            case CallbackType::BEFORE: {

                //Generate security process key.
                engine.GenerateProcessKey ();

                //Search outdated offsets.
                engine.SearchOffsets ();

            }; break;

            case CallbackType::AFTER: {

                //Destroy second application process.
                engine.DestroyChildProcess ();

            }; break;

        }

	};

private:

    FataEngine engine = Singleton <FataEngine> :: GetInstance ();

};