# UserAuth
This C++ project demonstrates a basic user authentication system using SHA-256 hashing.
It includes a `User` class that allows you to create user objects with associated attributes such as username, password, and email.
The core features of this project are as follows:

1. User Class
- The `User` class provides a blueprint for representing user accounts.
- It includes attributes for `username`, `password`, and `email`.
- A constructor initializes these attributes when creating a user object.

2. Password Hashing
- The project utilizes the OpenSSL library to perform SHA-256 hashing of user passwords.
- The `GetHashedPassword()` method takes a password as input and returns the SHA-256 hashed password as a formatted hexadecimal string.
- Proper formatting is ensured using C++'s `<sstream>` and `<iomanip>` libraries.

3. User Details Display
- The `PrintDetails()` method allows you to print user details to the console.
- It creates an instance of the `User` class with sample values for username, password, and email.
- It then calls the `PrintDetails()` method to display the user's details.

This project serves as a starting point for implementing user authentication systems and can be expanded upon for more complex applications.
It provides a simple yet effective way to securely hash passwords using SHA-256 in a C++ environment.

Feel free to fork, modify, and enhance this code to fit your specific authentication needs.
Enjoy exploring and learning from this project!
