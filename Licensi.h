#include <iostream>
#include <string>
#include "LSLog.cpp"

bool verifyLicense(const std::string& licenseKey) {
    const std::string validLicenseKey = "PRJCT-LOSTSAGA-2024";

    return licenseKey == validLicenseKey;
}

int main() {
    std::string licenseKey;
    std::cout << "Enter license key: ";
    std::cin >> licenseKey;

    if (verifyLicense(licenseKey)) {
        std::cout << "Pantek Mau Ngapain Kau.\n";
        
    }
    else {
        std::cout << "Ciee Mau Maling Yaa.\n";
       
    }

    return 0;
}