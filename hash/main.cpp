
#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;

int main() {
    string filename;

    cout << "Введите имя файла: ";
    getline(cin, filename);

    try {
        SHA256 hash;
        string result;

        FileSource file(
            filename.c_str(),
            true,
            new HashFilter(
                hash,
                new HexEncoder(
                    new StringSink(result),
                    false
                )
            )
        );

        cout << "SHA-256: " << result << endl;
    }
    catch (const Exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }

    return 0;
}

