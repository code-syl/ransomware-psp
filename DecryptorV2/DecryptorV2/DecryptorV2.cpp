#include <iostream>
#include <ShlObj_core.h>
#include <fstream>
#include <filesystem>

#include "../CryptoPP/cryptlib.h"
#include "../CryptoPP/rijndael.h"
#include "../CryptoPP/modes.h"
#include "../CryptoPP/files.h"
#include "../CryptoPP/osrng.h"
#include "../CryptoPP/hex.h"
struct Key {
    std::string iv;
    std::string key;
};

int readFileContents(const std::wstring* pathToFile, std::string* output);
std::string decryptAes(Key& key, std::string& cipher);
Key generateKey();
int changeDesktopWallpaper(const std::wstring backgroundImagePath);
bool fileExists(const std::wstring path);

int main() {
    // Constants
    const std::wstring SECRET_FOLDER_NAME = L"\\topsecret";
    wchar_t* documentsFolderPath;
    SHGetKnownFolderPath(FOLDERID_Documents, 0x00, NULL, &documentsFolderPath);
    const std::wstring SECRET_FOLDER_PATH(std::wstring(documentsFolderPath) + SECRET_FOLDER_NAME);
    const std::wstring NORMAL_PICTURE_PATH(std::wstring(documentsFolderPath) + L"\\NORMAL.jpg");

    // threat picture wallpaper
    int status = changeDesktopWallpaper(NORMAL_PICTURE_PATH);
    if (status < 0) return status;


    // Get files in 'topsecret' directory
    std::list<std::wstring> filesToDecrypt;
    for (const auto& entry : std::filesystem::directory_iterator(SECRET_FOLDER_PATH)) {
        if (entry.path().extension() == ".crypt0r") {
            filesToDecrypt.push_back(entry.path());
        }
    }

    // For each file, read contents, delete file, decrypt contents and make new file
    std::for_each(filesToDecrypt.begin(), filesToDecrypt.end(), [](std::wstring& filePath) {
        // Read contents
        std::wcout << L"# Opening file: \"" << filePath << "\"" << std::endl;
        std::string fileContents;
        readFileContents(&filePath, &fileContents);

        // Delete file
        std::wcout << L"# Deleting file: \"" << filePath << "\"" << std::endl;
        std::filesystem::remove(filePath);

        // Decrypt contents
        std::wcout << L"# Decrypting file: \"" << filePath << "\"" << std::endl;
        Key key = generateKey();
        std::string decryptedContents = decryptAes(key, fileContents);

        // Make new file with decrypted contents (file.txt.crypt0r -> file.txt)
        std::wstring newFilePath(filePath);
        newFilePath.erase(newFilePath.length() - 8); // 8 is size of crypt0r extension
        std::ofstream decryptedFile(newFilePath);
        decryptedFile << decryptedContents;
        decryptedFile.close();
        });

    return 0;
}

int readFileContents(const std::wstring* pathToFile, std::string* output) {
    std::ifstream file(*pathToFile);
    if (!file.is_open())
        return -1;

    char character;
    std::string contents;

    while (file) {
        character = file.get();
        contents += character;
    }

    file.close();
    *output = contents;

    return 0;
}

Key generateKey() {
    std::string rawKey = "adrivwm29akqi1mx";
    std::string rawIv = "ejw19ds9fj2nxizp";
    CryptoPP::SecByteBlock key((const CryptoPP::byte*)rawKey.data(), rawKey.size());
    CryptoPP::SecByteBlock iv((const CryptoPP::byte*)rawIv.data(), rawIv.size());

    std::string keyString((const char*)key.BytePtr(), key.size());
    std::string ivString((const char*)iv.BytePtr(), iv.size());

    Key keyOut;
    keyOut.iv = ivString;
    keyOut.key = keyString;

    return keyOut;
}

std::string decryptAes(Key& key, std::string& cipher) {
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor;
    const byte* keyData = (const byte*)&key.key[0];
    const byte* ivData = (const byte*)&key.iv[0];
    decryptor.SetKeyWithIV(keyData, key.key.size(), ivData);

    std::string plainText;

    CryptoPP::StringSource(cipher, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::StreamTransformationFilter(
                decryptor, new CryptoPP::StringSink(plainText))));

    return plainText;
}

bool fileExists(const std::wstring path) {
    return std::filesystem::exists(path);
}

int changeDesktopWallpaper(const std::wstring backgroundImagePath) {
    if (!fileExists(backgroundImagePath)) {
        std::cerr << "File \"" << backgroundImagePath.c_str() << "\" does not exist." << std::endl;

        return -1;
    }

    SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0x00, (void*)backgroundImagePath.c_str(), SPIF_UPDATEINIFILE);

    return 0;
}
