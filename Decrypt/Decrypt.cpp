#include <cstdio>
#include <cstring>
#include <Windows.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <shellapi.h>

// Disable warnings about unsafe CRT functions
#define _CRT_SECURE_NO_WARNINGS

// Function to decrypt a file using AES decryption with CBC mode
void Decrypt(const CryptoPP::byte key[], const CryptoPP::byte iv[], const wchar_t* inputFile, const wchar_t* outputFile) {
    // Open the input and output files
    FILE* ifs;
    _wfopen_s(&ifs, inputFile, L"rb");
    if (!ifs) {
        wprintf(L"Error opening input file: %s\n", inputFile);
        return;
    }

    FILE* ofs;
    _wfopen_s(&ofs, outputFile, L"wb");
    if (!ofs) {
        printf("Error opening output file.\n");
        fclose(ifs);
        return;
    }

    // Initialize the decryption cipher
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

    // Decrypt the input file and write it to the output file
    const int chunkSize = 4096;
    CryptoPP::byte input[chunkSize], output[chunkSize];
    while (true) {
        size_t bytesRead = fread(input, 1, chunkSize, ifs);
        if (bytesRead == 0) break;

        cbcDecryption.ProcessData(output, input, bytesRead);
        fwrite(output, 1, bytesRead, ofs);
    }
    
    printf("[+] Successfully decrypted the dump file provided.");

    // Close the input and output files
    fclose(ifs);
    fclose(ofs);
}


int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Please provide the input file as an argument.\n");
        return 0;
    }

    // Get wide command line arguments
    int numArgs;
    LPWSTR* szArglist = CommandLineToArgvW(GetCommandLineW(), &numArgs);
    if (NULL == szArglist) {
        wprintf(L"CommandLineToArgvW failed\n");
        return 0;
    }

    // Set the key and initialization vector for AES decryption
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };

    // Decrypt the input file and write it to a new file
    Decrypt(key, iv, szArglist[1], L"decrypted.dmp");

    // Free the memory allocated by CommandLineToArgvW
    LocalFree(szArglist);

    return 0;
}

