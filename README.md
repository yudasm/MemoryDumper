# MemoryDumper

MemoryDumper is a tool to create an encrypted memory dump of the lsass.exe process and then decrypt it offline to retrieve password hashes. The project consists of two parts: `MemoryDumper.cpp`, which creates the encrypted memory dump, and `Decrypt.cpp`, which decrypts the encrypted dump file.

At the time of release, the tool is able to dump the LSASS memory with Windows Defender on a Windows Server 2022.

**Note:** This tool is not intended for use against EDRs, as they pose a different challenge that requires advanced evasion techniques. We are currently working on developing tools specifically for this purpose, so stay tuned for future updates.

**Authors**:
- Tzach Benita (https://www.linkedin.com/in/tzach-benita/)
- Yehuda Smirnov (https://www.linkedin.com/in/yehuda-smirnov/)

## Prerequisites

- Visual Studio (or another C++ compiler)
- Crypto++ library

## How to compile

1. Clone the repository or download the source files.
2. Install the Crypto++ library: https://www.cryptopp.com/wiki/Visual_Studio
3. Create a new Visual Studio project and add the `MemoryDumper.cpp` and `Decrypt.cpp` files.
4. Set up the project to use the Crypto++ library.
5. Compile the project.

## Usage

1. Run the compiled MemoryDumper.exe with administrative privileges to create an encrypted memory dump of the lsass.exe process. The encrypted dump file will be saved as `encrypted_lsass.dmp` in the **C:\Windows\tasks\** directory.

2. To decrypt the encrypted memory dump, run the compiled Decrypt.exe and provide the path to the encrypted dump file as a command-line argument. The decrypted memory dump will be saved as `decrypted.dmp` in the same directory as Decrypt.exe.

## How It Works

### MemoryDumper.cpp

1. The program starts by enabling the `SeDebugPrivilege` and checking if it's running as an elevated process. This is necessary to access the lsass.exe process and dump its memory.

2. It creates a new file named `lsass.dmp` in the C:\Windows\tasks\ directory to store the memory dump.

3. The program searches for the lsass.exe process and retrieves its process ID.

4. It opens a handle to the lsass.exe process with `PROCESS_ALL_ACCESS` permission.

5. The program loads the `Dbghelp.dll` library and retrieves the `MiniDumpWriteDump` function address.

6. The `MiniDumpWriteDump` function is called with the lsass.exe process handle, process ID, and dump file handle, which creates a full memory dump of the lsass.exe process.

7. After creating the memory dump, the program encrypts it using the `EncFile` function, which utilizes the AES encryption algorithm with CBC mode. The encrypted dump is saved as `encrypted_lsass.dmp` in the C:\Windows\tasks\ directory.

8. The original, unencrypted memory dump (`lsass.dmp`) is deleted.

### Decrypt.cpp

1. The key and initialization vector (IV) used for AES decryption are defined in the source code. These values should match the ones used in the MemoryDumper.cpp for encryption.

2. The `Decrypt` function is called with the input file path, key, and IV. It reads the encrypted input file and decrypts it using the AES decryption algorithm with CBC mode. The decrypted data is written to a new file named `decrypted.dmp`.

The MemoryDumper and Decrypt programs work together to create an encrypted memory dump of the lsass.exe process and then decrypt it for further analysis. The encryption and decryption processes use the AES algorithm with CBC mode to ensure the dump does not get detected.

## Proof of Concept

<div align="center">
  <a href="https://www.youtube.com/watch?v=F_XO3SCewqo">
    <img src="https://img.youtube.com/vi/F_XO3SCewqo/0.jpg" alt="IMAGE_DESCRIPTION">
  </a>
</div>


## Contributing

Contributions are welcome! If you have any ideas or improvements, please submit a pull request or open an issue to discuss the changes.

## License

This project is licensed under the [MIT License](LICENSE). Please see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for educational and research purposes only. The authors are not responsible for any damage caused by the misuse of this tool.
