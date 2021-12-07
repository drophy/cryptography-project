#include <iostream>
#include <fstream> // to read/write to files
#include <string> // for getline
#include <sstream> // to use stuff like stringstream
#include <iomanip> // for setw and setfill
#include "sodium.h"

int useless_int;

// FUNCTION HEADERS
void genKeyPair(std::string public_key_path, std::string secret_key_path);
void genSecretKey(std::string key_path, std::string nonce_path);
int encryptFile(std::string input_path, std::string output_path, std::string key_path, std::string nonce_path);
int decryptFile(std::string input_path, std::string output_path, std::string key_path, std::string nonce_path);
int signFile(std::string input_path, std::string output_path, std::string private_key_path);
bool valSignature(std::string input_path, std::string output_path, std::string public_key_path);

void writeFileHex(std::string file_path, unsigned char* text, int text_length);
void writeFile(std::string file_path, unsigned char* text, int text_length);
unsigned char* readFileHex(std::string input_path, int* input_size = &useless_int);
std::string readFile(std::string input_path);

// MAIN
int main()
{
    // Load Libsodium
    if (sodium_init() < 0) {
        std::cout << "Could not load libsodium D:!\n";
        return -1;
    }

    // Display menu
    bool exit = false;
    while (!exit)
    {
        std::cout << "\n\n1) Generate a secret key for symmetric encryption\n";
        std::cout << "2) Generate a private and public key-pair\n";
        std::cout << "3) Encrypt a file\n";
        std::cout << "4) Decrypt a file\n";
        std::cout << "5) Sign a file\n";
        std::cout << "6) Verify signed file\n";
        std::cout << "7) Exit\n\n";

        // Allow user to pick action
        int choice;
        std::string str_choice;

        // https://stackoverflow.com/questions/7786994/c-getline-isnt-waiting-for-input-from-console-when-called-multiple-times
        std::cout << "Pick an option: ";
        std::getline(std::cin, str_choice); // using std::cin >> choice was not working along well with the other 'getline's
        choice = std::stoi(str_choice); // stoi = string to int

        // Execute action
        std::string input_path, output_path, key_path, nonce_path, pk_path, sk_path;
        switch (choice)
        {
        case 1:
          
            // TODO: wait, the input still doesn't work correctly :/ ~ e.g. if you only set the key name
            std::cout << "Key file name (key.txt): ";
            std::getline(std::cin, key_path);
            std::cout << "Nonce file name (nonce.txt): ";
            std::getline(std::cin, nonce_path);

            if (key_path.empty()) key_path = "key.txt";
            if (nonce_path.empty()) nonce_path = "nonce.txt";
            genSecretKey(key_path, nonce_path);
            break;

        case 2:
            std::cout << "Public key file name (public_key.txt): ";
            std::getline(std::cin, pk_path);
            std::cout << "Private key file name (private_key.txt): ";
            std::getline(std::cin, sk_path);

            if (pk_path.empty()) pk_path = "public_key.txt";
            if (sk_path.empty()) sk_path = "private_key.txt";
            genKeyPair(pk_path, sk_path);
            break;

        case 3:
            std::cout << "Message file name (message.txt): ";
            std::getline(std::cin, input_path);
            std::cout << "Output file name (ciphered.txt): ";
            std::getline(std::cin, output_path);
            std::cout << "Key file name (key.txt): ";
            std::getline(std::cin, key_path);
            std::cout << "Nonce file name (nonce.txt): ";
            std::getline(std::cin, nonce_path);

            if (input_path.empty()) input_path = "message.txt";
            if (output_path.empty()) output_path = "ciphered.txt";
            if (key_path.empty()) key_path = "key.txt";
            if (nonce_path.empty()) nonce_path = "nonce.txt";
            if (encryptFile(input_path, output_path, key_path, nonce_path) != 0)
                return -1;
            break;

        case 4:
            std::cout << "Encrypted message file name (ciphered.txt): ";
            std::getline(std::cin, input_path);
            std::cout << "Output file name (deciphered.txt): ";
            std::getline(std::cin, output_path);
            std::cout << "Key file name (key.txt): ";
            std::getline(std::cin, key_path);
            std::cout << "Nonce file name (nonce.txt): ";
            std::getline(std::cin, nonce_path);

            if (input_path.empty()) input_path = "ciphered.txt";
            if (output_path.empty()) output_path = "deciphered.txt";
            if (key_path.empty()) key_path = "key.txt";
            if (nonce_path.empty()) nonce_path = "nonce.txt";
            if (decryptFile(input_path, output_path, key_path, nonce_path) != 0)
                return -1;
            break;

        case 5:
            std::cout << "Message file name (message.txt): ";
            std::getline(std::cin, input_path);
            std::cout << "Output file name (signed.txt): ";
            std::getline(std::cin, output_path);
            std::cout << "Private key file name (private_key.txt): ";
            std::getline(std::cin, sk_path);

            if (input_path.empty()) input_path = "message.txt";
            if (output_path.empty()) output_path = "signed.txt";
            if (sk_path.empty()) sk_path = "private_key.txt";
            if (signFile(input_path, output_path, sk_path) != 0)
                return -1;
            break;

        case 6:
            std::cout << "Signed message file name (signed.txt): ";
            std::getline(std::cin, input_path);
            std::cout << "Output file name (unsigned.txt): ";
            std::getline(std::cin, output_path);
            std::cout << "Public key file name (public_key.txt): ";
            std::getline(std::cin, pk_path);

            if (input_path.empty()) input_path = "signed.txt";
            if (output_path.empty()) output_path = "unsigned.txt";
            if (pk_path.empty()) pk_path = "public_key.txt";
            valSignature(input_path, output_path, pk_path);
            break;

        default:
            exit = true;
            break;
        }
    }

    std::cout << "Execution complete!\n";
    return 0;
}

// OPTION ROUTINES
void genKeyPair(std::string public_key_path, std::string private_key_path)
{
    // Generate keys
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(public_key, private_key);


    // Write them to the specified files
    writeFileHex(public_key_path, public_key, sizeof(public_key));
    writeFileHex(private_key_path, private_key, sizeof(private_key));
}

void genSecretKey(std::string key_path, std::string nonce_path)
{
    // Gen key and nonce
    unsigned char key[crypto_stream_chacha20_KEYBYTES];
    unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];
    crypto_secretbox_keygen(key);
    randombytes_buf(nonce, sizeof(nonce));

    // Write them to the specified files
    writeFileHex(key_path, key, sizeof(key));
    writeFileHex(nonce_path, nonce, sizeof(nonce));
}

int encryptFile(std::string input_path, std::string output_path, std::string key_path, std::string nonce_path)
{
    // Read text, key and nonce
    std::string input = readFile(input_path);
    unsigned char* key = readFileHex(key_path);
    unsigned char* nonce = readFileHex(nonce_path);

    // Cypher text
    //std::cout << "About to cipher text of size " << input.length() << std::endl; // debug
    unsigned char* cipher_text = new unsigned char[input.length()];
    int error_code = crypto_stream_chacha20_xor(
        cipher_text, 
        (unsigned char*)input.c_str(), 
        input.length(), 
        nonce,
        key
    );

    if (error_code != 0) {
        std::cout << "Error while cyphering. Code: " << error_code << std::endl;
        return error_code;
    }

    // Write to file
    writeFileHex(output_path, cipher_text, input.length());
    return 0;
}

int decryptFile(std::string input_path, std::string output_path, std::string key_path, std::string nonce_path)
{
    // Read text, key and nonce
    int input_size;
    unsigned char* input = readFileHex(input_path, &input_size);
    unsigned char* key = readFileHex(key_path);
    unsigned char* nonce = readFileHex(nonce_path);

    // Decipher text
    unsigned char* deciphered_text = new unsigned char[input_size];
    int error_code = crypto_stream_chacha20_xor(
        deciphered_text, 
        input, 
        input_size,
        nonce,
        key
    );
    if (error_code != 0) {
        std::cout << "Error while decyphering. Code: " << error_code << std::endl;
        return error_code;
    }

    // Write to file
    writeFile(output_path, deciphered_text, input_size);
    return 0;
}

int signFile(std::string input_path, std::string output_path, std::string private_key_path)
{
    // Read message and private key
    std::string input = readFile(input_path);
    unsigned char* key = readFileHex(private_key_path);

    // Sign message
    unsigned char* signed_message = new unsigned char[crypto_sign_BYTES + input.length()];;
    unsigned long long signed_message_len;

    crypto_sign(
        signed_message, 
        &signed_message_len,
        (unsigned char*) input.c_str(), 
        input.length(), 
        key
    );

    // Write to file
    writeFileHex(output_path, signed_message, signed_message_len);
    return 0;
}

bool valSignature(std::string input_path, std::string output_path, std::string public_key_path)
{
    // Read signed message and public key
    int input_length;
    unsigned char* input = readFileHex(input_path, &input_length);
    unsigned char* key = readFileHex(public_key_path);

    // Validate signature
    unsigned char* unsigned_message = new unsigned char [input_length];
    unsigned long long unsigned_message_len;
    int res = crypto_sign_open(unsigned_message, &unsigned_message_len, input, input_length, key);

    if (res != 0) {
        std::cout << "The signature is not valid! :O" << std::endl;
        return false;
    }
    std::cout << "The signature is valid! :D" << std::endl;
    
    // Write to file
    writeFile(output_path, unsigned_message, unsigned_message_len);
    return true;
}

// HELPER FUNCTIONS
void writeFileHex(std::string file_path, unsigned char* text, int text_length)
{
    std::fstream output_file;
    output_file.open(file_path, std::ios::out);
    if (!output_file.is_open()) {
        std::cout << "Error: could not create file: " + file_path << std::endl;
    }
    for (int i = 0; i < text_length; i++) {
        // https://coderedirect.com/questions/56190/integer-to-hex-string-in-c
        output_file << std::setfill('0') << std::setw(2) << std::hex << int(text[i]);
    }
    output_file.close();
    std::cout << "Wrote file: " + file_path << ". Len was " << text_length << std::endl;
}

void writeFile(std::string file_path, unsigned char* text, int text_length)
{
    std::fstream output_file;
    output_file.open(file_path, std::ios::out);
    if (!output_file.is_open()) {
        std::cout << "Error: could not create file: " + file_path << std::endl;
    }
    for (int i = 0; i < text_length; i++) {
        output_file << text[i];
    }
    output_file.close();
    std::cout << "Wrote file: " + file_path << ". Len was " << text_length << std::endl;
}

unsigned char* readFileHex(std::string input_path, int* input_size)
{
    std::fstream input_file;
    input_file.open(input_path, std::ios::in);
    if (!input_file.is_open()) {
        std::cout << "Error: could not find or open file " << input_path << std::endl;
        unsigned char* idk = new unsigned char[1];
        return idk;
    }

    std::string text = "";
    std::string line;
    while (getline(input_file, line)) text += line + '\n';
    input_file.close();
    text.pop_back(); // remove last \n

    // Convert from hex to char
    unsigned int n;
    unsigned char* char_text = new unsigned char[text.length()/2];
    for (int i = 0; i < text.length(); i += 2) {
        // https://stackoverflow.com/questions/1070497/c-convert-hex-string-to-signed-integer
        std::stringstream ss;
        ss << std::hex << text[i] << text[i+1];
        ss >> n;
        //std::cout << n << "-"; // debug
        // https://en.cppreference.com/w/cpp/io/manip/hex
        //std::istringstream(text[i]) >> std::hex >> n; // another option
        char_text[i / 2] = char(n);
    }
    //std::cout << std::endl;

    // std::cout << "Read from file Len: " << text.length() / 2 << std::endl; // dbug
    *input_size = text.length() / 2;
    return char_text;
}

std::string readFile(std::string input_path)
{
    std::fstream input_file;
    input_file.open(input_path, std::ios::in);
    if (!input_file.is_open()) {
        std::cout << "Error: could not find or open file " << input_path << std::endl;
        return "";
    }

    std::string text = "";
    std::string line;
    while (getline(input_file, line)) text += line + '\n';
    input_file.close();
    text.pop_back(); // remove last \n

    // std::cout << "Read from file: " /* << text*/ << ". Len: " << text.length() << std::endl; // dbug
    return text;
}