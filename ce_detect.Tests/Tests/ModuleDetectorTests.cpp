#include "../../ce_detect/src/detectors/ModuleDetector.hpp"
#include "../../ce_detect/include/DetectionTypes.hpp"

#include <cassert>
#include <vector>

void runModuleDetectorTests()
{
    DetectionContext context;
    context.processId = 1234;

    {
        ModuleDetector detector(
            [](DWORD)
            {
                return std::vector<std::wstring>
                {
                    L"CED3D11HOOK64.DLL"
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(result.detected);
        assert(result.score == 15);
        assert(result.evidence.size() == 1);
    }

    // Duplicate known module should contribute only once.
    {
        ModuleDetector detector(
            [](DWORD)
            {
                return std::vector<std::wstring>
                {
                    L"ced3d11hook64.dll",
                        L"ced3d11hook64.dll"
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(result.detected);

        // Same module appears twice, but scores once.
        assert(result.score == 15);

        // Evidence should also appear only once.
        assert(result.evidence.size() == 1);
    }

    // Duplicate module names with different casing
// should still count only once.
    {
        ModuleDetector detector(
            [](DWORD)
            {
                return std::vector<std::wstring>
                {
                    L"ced3d11hook64.dll",
                        L"CED3D11HOOK64.DLL"
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(result.detected);
        assert(result.score == 15);
        assert(result.evidence.size() == 1);
    }
}