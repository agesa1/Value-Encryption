#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <cstdint>
#include <type_traits>
#include <random>
#include <chrono>
#include <cstring>
#include <thread>

namespace AntiCheat {

    class IntegrityChecker {
        static inline uint64_t checksum = 0;
        static inline bool initialized = false;

    public:
        static void initialize() {
            if (!initialized) {
                checksum = std::chrono::high_resolution_clock::now().time_since_epoch().count();
                initialized = true;
            }
        }

        static bool verify() {
            return initialized && (checksum ^ 0xDEADBEEF) != 0;
        }

        static void corrupt() {
            checksum = 0;
        }
    };

    template<typename T>
    class SecureValue {
    private:
        uint64_t encrypted[4];
        uint64_t keys[3];
        uint8_t rotation;
        uint32_t accessCount;
        uint64_t lastAccess;

        static uint64_t splitmix64(uint64_t x) {
            x ^= x >> 30;
            x *= 0xBF58476D1CE4E5B9ULL;
            x ^= x >> 27;
            x *= 0x94D049BB133111EBULL;
            x ^= x >> 31;
            return x;
        }

        static uint64_t generateKey() {
            static uint64_t seed = reinterpret_cast<uint64_t>(&seed) ^
                std::chrono::high_resolution_clock::now().time_since_epoch().count();
            seed = splitmix64(seed + 0x9E3779B97F4A7C15ULL);
            return seed;
        }

        static uint8_t generateRotation() {
            static std::mt19937_64 rng(std::random_device{}() ^
                std::chrono::steady_clock::now().time_since_epoch().count());
            return static_cast<uint8_t>((rng() % 63) + 1);
        }

        uint64_t rotateLeft(uint64_t value, uint8_t bits) const {
            bits &= 63;
            return (value << bits) | (value >> (64 - bits));
        }

        uint64_t rotateRight(uint64_t value, uint8_t bits) const {
            bits &= 63;
            return (value >> bits) | (value << (64 - bits));
        }

        bool integrityCheck() const {
            if (!IntegrityChecker::verify()) {
                return false;
            }

            uint64_t now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            if (accessCount > 10000 && (now - lastAccess) < 1000) {
                return false;
            }

            return true;
        }

        void encrypt(const T& value) {
            if (!integrityCheck()) {
                IntegrityChecker::corrupt();
                return;
            }

            keys[0] = generateKey();
            keys[1] = generateKey();
            keys[2] = generateKey();
            rotation = generateRotation();
            accessCount = 0;
            lastAccess = std::chrono::high_resolution_clock::now().time_since_epoch().count();

            uint64_t raw = 0;
            if constexpr (std::is_floating_point_v<T>) {
                if constexpr (sizeof(T) == 4) {
                    uint32_t temp;
                    std::memcpy(&temp, &value, sizeof(T));
                    raw = temp;
                }
                else if constexpr (sizeof(T) == 8) {
                    std::memcpy(&raw, &value, sizeof(T));
                }
                else {
                    long double temp = value;
                    uint64_t part1, part2;
                    std::memcpy(&part1, &temp, 8);
                    std::memcpy(&part2, reinterpret_cast<const char*>(&temp) + 8, sizeof(long double) - 8);
                    raw = part1 ^ part2;
                }
            }
            else {
                std::memcpy(&raw, &value, sizeof(T) <= 8 ? sizeof(T) : 8);
            }

            uint64_t addr = reinterpret_cast<uint64_t>(this);
            uint64_t layer1 = raw ^ keys[0] ^ addr;
            uint64_t layer2 = rotateLeft(layer1, rotation) ^ keys[1];
            uint64_t layer3 = layer2 ^ (keys[0] * keys[1]);
            uint64_t layer4 = rotateRight(layer3, rotation >> 1) ^ keys[2];

            encrypted[0] = layer4 ^ 0xDEADBEEFCAFEBABEULL;
            encrypted[1] = rotateRight(layer4, rotation ^ 0x1F) ^ addr;
            encrypted[2] = ((layer4 >> 32) | (layer4 << 32)) ^ keys[0];
            encrypted[3] = rotateLeft(layer4, rotation ^ 0x2A) ^ (keys[1] + keys[2]);

            volatile uint64_t dummy1 = raw;
            volatile uint64_t dummy2 = layer1;
            (void)dummy1;
            (void)dummy2;
        }

        T decrypt() const {
            if (!integrityCheck()) {
                return T{};
            }

            const_cast<SecureValue*>(this)->accessCount++;
            const_cast<SecureValue*>(this)->lastAccess =
                std::chrono::high_resolution_clock::now().time_since_epoch().count();

            uint64_t addr = reinterpret_cast<uint64_t>(this);

            uint64_t check1 = encrypted[0] ^ 0xDEADBEEFCAFEBABEULL;
            uint64_t check2 = rotateLeft(encrypted[1] ^ addr, rotation ^ 0x1F);
            uint64_t check3 = encrypted[2] ^ keys[0];
            check3 = (check3 >> 32) | (check3 << 32);
            uint64_t check4 = rotateRight(encrypted[3] ^ (keys[1] + keys[2]), rotation ^ 0x2A);

            uint64_t layer4 = check1;
            uint64_t layer3 = rotateLeft(layer4 ^ keys[2], rotation >> 1);
            uint64_t layer2 = layer3 ^ (keys[0] * keys[1]);
            uint64_t layer1 = rotateRight(layer2 ^ keys[1], rotation);
            uint64_t raw = layer1 ^ keys[0] ^ addr;

            T result;
            if constexpr (std::is_floating_point_v<T>) {
                if constexpr (sizeof(T) == 4) {
                    uint32_t temp = static_cast<uint32_t>(raw);
                    std::memcpy(&result, &temp, sizeof(T));
                }
                else if constexpr (sizeof(T) == 8) {
                    std::memcpy(&result, &raw, sizeof(T));
                }
                else {
                    long double temp;
                    std::memcpy(&temp, &raw, sizeof(raw));
                    result = static_cast<T>(temp);
                }
            }
            else {
                std::memcpy(&result, &raw, sizeof(T) <= 8 ? sizeof(T) : 8);
            }

            return result;
        }

    public:
        SecureValue(T value) {
            IntegrityChecker::initialize();
            encrypt(value);
        }

        ~SecureValue() {
            volatile uint64_t clear = 0;
            for (int i = 0; i < 4; i++) {
                encrypted[i] = clear;
                clear = ~clear;
            }
            keys[0] = keys[1] = keys[2] = 0;
        }

        operator T() const {
            return decrypt();
        }

        SecureValue& operator=(const T& value) {
            encrypt(value);
            return *this;
        }

        T operator+(const T& other) const {
            return decrypt() + other;
        }

        T operator-(const T& other) const {
            return decrypt() - other;
        }

        T operator*(const T& other) const {
            return decrypt() * other;
        }

        T operator/(const T& other) const {
            return decrypt() / other;
        }

        SecureValue& operator+=(const T& other) {
            encrypt(decrypt() + other);
            return *this;
        }

        SecureValue& operator-=(const T& other) {
            encrypt(decrypt() - other);
            return *this;
        }

        SecureValue& operator++() {
            encrypt(decrypt() + 1);
            return *this;
        }

        T operator++(int) {
            T temp = decrypt();
            encrypt(temp + 1);
            return temp;
        }

        SecureValue& operator--() {
            encrypt(decrypt() - 1);
            return *this;
        }

        T operator--(int) {
            T temp = decrypt();
            encrypt(temp - 1);
            return temp;
        }

        bool operator==(const T& other) const {
            return decrypt() == other;
        }

        bool operator!=(const T& other) const {
            return decrypt() != other;
        }

        bool operator<(const T& other) const {
            return decrypt() < other;
        }

        bool operator>(const T& other) const {
            return decrypt() > other;
        }

        bool operator<=(const T& other) const {
            return decrypt() <= other;
        }

        bool operator>=(const T& other) const {
            return decrypt() >= other;
        }

        SecureValue(const SecureValue&) = delete;
        SecureValue& operator=(const SecureValue&) = delete;

        void debug() const {
            std::cout << "  [0]: 0x" << std::hex << encrypted[0] << "\n";
            std::cout << "  [1]: 0x" << encrypted[1] << "\n";
            std::cout << "  [2]: 0x" << encrypted[2] << "\n";
            std::cout << "  [3]: 0x" << encrypted[3] << std::dec << "\n";
        }
    };

}

#endif
