#include <iostream>
#include <openssl/sha.h>
#include <cstring>
#include <sstream>
#include <iomanip>

class User {
    public:
        std::string username;
        const char * password;
        std::string email;

        User(std::string Username, const char * Password, std::string EMail) {
            username = Username;
            password = Password;
            email = EMail;
        }

        const std::string GetHashedPassword(const char* password) {
            unsigned char hash[SHA256_DIGEST_LENGTH];

            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, password, strlen(password));
            SHA256_Final(hash, &sha256);

            std::stringstream ss;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
            }

            return ss.str();
        }

        void PrintDetails() {
            std::cout << "------------------------------------" << std::endl;
            std::cout << "Username: " << username << std::endl;
            std::cout << "Password: " << GetHashedPassword(password) << std::endl;
            std::cout << "E-Mail: " << email << std::endl;
            std::cout << "------------------------------------" << std::endl;
        }
};

int main() {
    User user1("VoidableMethod", "MySecurePassword", "voidablemethod@gmail.com");
    user1.PrintDetails();
    
    return 0;
}