
#include <iostream>
#include <string>
#include <stdexcept>
#include <cstring>

#include <cryptopp/aes.h>
#include <cryptopp/twofish.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>

using namespace std;
using namespace CryptoPP;

const int SALT_SIZE = 16;
const int IV_SIZE = 16;
const int KEY_SIZE = 32;
const int ITERATIONS = 100000;

// Получение ключей из пароля
void deriveKeys(const string& password,
                const CryptoPP::byte* salt, CryptoPP::byte* keys) {
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;

    pbkdf.DeriveKey(
        keys, 64, 0,
        reinterpret_cast<const CryptoPP::byte*>(password.data()),
        password.size(),
        salt, SALT_SIZE, ITERATIONS
    );
}

// Шифрование или расшифрование в CBC
string processCBC(const string& data,
                  const CryptoPP::byte* key, const CryptoPP::byte* iv,
                  int algorithm, bool encrypt) {
    string result;

    if (algorithm == 1) {
        if (encrypt) {
            CBC_Mode<AES>::Encryption enc;
            enc.SetKeyWithIV(key, KEY_SIZE, iv, IV_SIZE);

            StringSource(data, true,
                new StreamTransformationFilter(
                    enc, new StringSink(result)
                )
            );
        } else {
            CBC_Mode<AES>::Decryption dec;
            dec.SetKeyWithIV(key, KEY_SIZE, iv, IV_SIZE);

            StringSource(data, true,
                new StreamTransformationFilter(
                    dec, new StringSink(result)
                )
            );
        }
    } else {
        if (encrypt) {
            CBC_Mode<Twofish>::Encryption enc;
            enc.SetKeyWithIV(key, KEY_SIZE, iv, IV_SIZE);

            StringSource(data, true,
                new StreamTransformationFilter(
                    enc, new StringSink(result)
                )
            );
        } else {
            CBC_Mode<Twofish>::Decryption dec;
            dec.SetKeyWithIV(key, KEY_SIZE, iv, IV_SIZE);

            StringSource(data, true,
                new StreamTransformationFilter(
                    dec, new StringSink(result)
                )
            );
        }
    }

    return result;
}

int main() {
    int operation, algorithm;
    string inputFile, outputFile, password;

    cout << "1 - Зашифровать файл\n";
    cout << "2 - Расшифровать файл\n";
    cout << "Выберите операцию: ";
    if (!(cin >> operation) ||
        (operation != 1 && operation != 2)) {
        cerr << "Неверная операция\n";
        return 1;
    }

    if (operation == 1) {
        cout << "1 - AES-256-CBC\n";
        cout << "2 - Twofish-CBC\n";
        cout << "Выберите алгоритм: ";
        if (!(cin >> algorithm) ||
            (algorithm != 1 && algorithm != 2)) {
            cerr << "Неверный алгоритм\n";
            return 1;
        }
    }

    cin.ignore(10000, '\n');

    cout << "Исходный файл: ";
    getline(cin, inputFile);

    cout << "Выходной файл: ";
    getline(cin, outputFile);

    if (inputFile.empty() || outputFile.empty() ||
        inputFile == outputFile) {
        cerr << "Некорректные имена файлов\n";
        return 1;
    }

    cout << "Введите пароль: ";
    getline(cin, password);

    if (password.empty()) {
        cerr << "Пароль не может быть пустым\n";
        return 1;
    }

    try {
        string data;
        FileSource(inputFile.c_str(), true,
                   new StringSink(data));

        string result;
        CryptoPP::byte salt[SALT_SIZE];
        CryptoPP::byte iv[IV_SIZE];
        CryptoPP::byte keys[64];

        if (operation == 1) {
            AutoSeededRandomPool rng;
            rng.GenerateBlock(salt, SALT_SIZE);
            rng.GenerateBlock(iv, IV_SIZE);

            deriveKeys(password, salt, keys);

            string encrypted = processCBC(
                data, keys, iv, algorithm, true
            );

            result = "CP01";
            result += static_cast<char>(algorithm);
            result.append(
                reinterpret_cast<const char*>(salt),
                SALT_SIZE
            );
            result.append(
                reinterpret_cast<const char*>(iv),
                IV_SIZE
            );
            result += encrypted;

            HMAC<SHA256> hmac(keys + KEY_SIZE, KEY_SIZE);
            CryptoPP::byte tag[SHA256::DIGESTSIZE];

            hmac.CalculateDigest(
                tag,
                reinterpret_cast<const CryptoPP::byte*>(result.data()),
                result.size()
            );

            result.append(
                reinterpret_cast<const char*>(tag),
                sizeof(tag)
            );

        } else {
            const size_t headerSize = 5 + SALT_SIZE + IV_SIZE;
            const size_t tagSize = SHA256::DIGESTSIZE;

            if (data.size() < headerSize + tagSize + 16 ||
                data.substr(0, 4) != "CP01") {
                throw runtime_error(
                    "Неверный формат зашифрованного файла"
                );
            }

            algorithm = data[4];

            if (algorithm != 1 && algorithm != 2) {
                throw runtime_error("Неизвестный алгоритм");
            }

            memcpy(salt, data.data() + 5, SALT_SIZE);
            memcpy(iv, data.data() + 5 + SALT_SIZE, IV_SIZE);

            deriveKeys(password, salt, keys);

            HMAC<SHA256> hmac(keys + KEY_SIZE, KEY_SIZE);

            const CryptoPP::byte* tag =
                reinterpret_cast<const CryptoPP::byte*>(
                    data.data() + data.size() - tagSize
                );

            if (!hmac.VerifyDigest(
                    tag,
                    reinterpret_cast<const CryptoPP::byte*>(data.data()),
                    data.size() - tagSize)) {
                throw runtime_error(
                    "Неверный пароль или повреждён файл"
                );
            }

            string encrypted = data.substr(
                headerSize,
                data.size() - headerSize - tagSize
            );

            result = processCBC(
                encrypted, keys, iv, algorithm, false
            );
        }

        FileSink output(outputFile.c_str(), true);
        output.Put(
            reinterpret_cast<const CryptoPP::byte*>(result.data()),
            result.size()
        );
        output.MessageEnd();

        cout << (operation == 1
            ? "Файл успешно зашифрован!"
            : "Файл успешно расшифрован!") << endl;

    } catch (const std::exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }

    return 0;
}
