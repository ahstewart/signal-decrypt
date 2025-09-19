# Database Decryptor for Signal Messenger

This is a simple .NET application designed to decrypt the SQLCipher-encrypted SQLite database file that stores the Signal Desktop message data. It uses the sqlcipher_export() function to output a deencrypted SQLite database file.

The SQLitePCLRaw.bundle_sqlcipher package is used to handle the actual database decrpytion.

## Features

* Decrypts SQLCipher-encrypted SQLite databases
* Supports Signal Desktop databases with encrypted keys (before 2024 or so, Signal database keys were not encrypted)
* Cross-platform (Windows, macOS, Linux)

## How to Use

Self-contained executables (64-bit) are provided for each of the 3 common operating systems. 

Navigate to /bin/Release/{your_operating_system}/public, download the appropriate file to your machine, and run it. 

You will be prompted several times for things like desired output path and the name of the decrypted database.
