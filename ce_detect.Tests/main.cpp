// tests/main.cpp

#include <iostream>

void runConfidenceLevelTests();
void runModuleDetectorTests();
void runMemoryPatternMatcherTests();
void runMemorySignatureDetectorTests();
void runProcessMetadataDetectorTests();
void runSignatureFamilyMatcherTests();
void runFirstScanSignatureRegressionTests();

int main()
{
    runConfidenceLevelTests();
    runModuleDetectorTests();
    runMemoryPatternMatcherTests();
    runMemorySignatureDetectorTests();
    runProcessMetadataDetectorTests();
    runSignatureFamilyMatcherTests();

    runFirstScanSignatureRegressionTests();

    std::cout << "All tests passed.\n";
    return 0;
}