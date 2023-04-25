# MemoryDumper

MemoryDumper is a tool designed to dump the memory of a process using MiniDumpWriteDump, specifically LSASS. 
It encrypts the resulting memory dump to evade antivirus detection and deletion of the written dump. 

*Note:* This tool is not designed to evade Endpoint Detection and Response (EDR) systems, as they are a different challenge. A new tool addressing EDRs is currently in development.

## Files

- `MemoryDumper.cpp`: This file is responsible for dumping the process memory and encrypting the memory dump.
- `decrypt.cpp`: This file is responsible for decrypting the encrypted memory dump.

## Usage

### MemoryDumper.exe

1. Compile the `MemoryDumper.cpp` file.
2. Run `MemoryDumper.exe <process ID>` to dump and encrypt the memory of the specified process.

### decrypt.exe

1. Compile the `decrypt.cpp` file.
2. Run `decrypt.exe <path to encrypted file>` to decrypt the encrypted memory dump. The decrypted dump will be saved as `decrypted.dmp`.

## How it Works

1. Obtain the process handle: MemoryDumper takes the process ID as an argument and opens a handle to the process using the OpenProcess function.
2. Create a dump file: MemoryDumper creates a new file named "dump.dmp" using the CreateFileW function.
3. Dump the process memory: The MiniDumpWriteDump function is used to write the process memory to the "dump.dmp" file.
4. Encrypt the memory dump: After creating the memory dump, the tool encrypts the dump file using AES encryption with CBC mode. The Crypto++ library is used to perform the encryption. The key and initialization vector (IV) are hardcoded in the source code. The encrypted dump file is saved as "dump_encrypted.dmp".
5. Delete the original memory dump: After the encryption is complete, the original memory dump file is deleted using the DeleteFileW function.

The `decrypt.exe` utility uses the same key and IV as the encryption process to decrypt the file.

## Contributing

Contributions are welcome! If you have any ideas or improvements, please submit a pull request or open an issue to discuss the changes.

## License

This project is licensed under the [MIT License](LICENSE). Please see the [LICENSE](LICENSE) file for details.
