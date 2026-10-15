#include "ConsoleReporter.hpp"
#include "DetectionEngine.hpp"

#include "detectors/ModuleDetector.hpp"
#include "detectors/ProcessMetadataDetector.hpp"
#include "detectors/ProcessNameDetector.hpp"
#include "detectors/WindowDetector.hpp"
#include "detectors/MemorySignatureDetector.hpp"
#include "detectors/DriverDetector.hpp"

#include <iostream>
#include <memory>

int main()
{
    std::cout
        << "Cheat Engine Detector\n"
        << "=====================\n\n";

    DetectionEngine engine;

    engine.addDetector(
        std::make_unique<ProcessNameDetector>()
    );

    engine.addDetector(
        std::make_unique<ProcessMetadataDetector>()
    );

    engine.addDetector(
        std::make_unique<ModuleDetector>()
    );

    engine.addDetector(
        std::make_unique<WindowDetector>()
    );

    engine.addDetector(
        std::make_unique<MemorySignatureDetector>()
    );

    engine.addSystemDetector(
        std::make_unique<DriverDetector>()
    );

    std::cout
        << "Scanning running processes...\n\n";

    const auto reports =
        engine.scanProcesses();

    ConsoleReporter reporter;
    reporter.print(reports);

    return 0;
}