#include <iostream>
#include <openssl/sha.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <ctime>

class User {
public:
    std::string username;
    std::string email;
    std::string salt; // Add salt for password hashing
    std::string hashedPassword; // Store the hashed password

    User(std::string Username, std::string EMail) {
        username = Username;
        email = EMail;
        GenerateSalt(); // Generate a random salt
        ComputeAndStoreHashedPassword("MySecurePassword"); // Hash and store the password
    }

    // Generate a random salt and store it
    void GenerateSalt() {
        // Initialize random seed
        std::srand(static_cast<unsigned int>(std::time(nullptr)));

        // Generate a random salt (you can customize its length)
        const int saltLength = 16; // For example, a 128-bit salt
        const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        const int charsetSize = sizeof(charset) - 1;

        for (int i = 0; i < saltLength; ++i) {
            salt += charset[std::rand() % charsetSize];
        }
    }

    // Compute and store the hashed password using the salt
    void ComputeAndStoreHashedPassword(const std::string& password) {
        // Combine the password and salt
        std::string passwordWithSalt = password + salt;

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, passwordWithSalt.c_str(), passwordWithSalt.length());
        SHA256_Final(hash, &sha256);

        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }

        hashedPassword = ss.str();
    }

    // Verify a password
    bool VerifyPassword(const std::string& password) {
        // Combine the provided password with the stored salt
        std::string passwordWithSalt = password + salt;

        // Compute the hash of the provided password with the stored salt
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, passwordWithSalt.c_str(), passwordWithSalt.length());
        SHA256_Final(hash, &sha256);

        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }

        std::string hashedInputPassword = ss.str();

        // Compare the computed hash with the stored hashed password
        return hashedInputPassword == hashedPassword;
    }

    void PrintDetails() {
        std::cout << "------------------------------------" << std::endl;
        std::cout << "Username: " << username << std::endl;
        std::cout << "E-Mail: " << email << std::endl;
        std::cout << "Salt: " << salt << std::endl;
        std::cout << "Hashed Password: " << hashedPassword << std::endl;
        std::cout << "------------------------------------" << std::endl;
    }
};

int main() {
    User user1("VoidableMethod", "voidablemethod@gmail.com");
    user1.PrintDetails();

    // Verify a password
    if (user1.VerifyPassword("MySecurePassword")) {
        std::cout << "Password is correct!" << std::endl;
    } else {
        std::cout << "Password is incorrect." << std::endl;
    }

    return 0;
}
