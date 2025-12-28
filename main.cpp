#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
#include "encrypt.h"

using namespace AntiCheat;

int main() {
    SecureValue<int> health(100);
    SecureValue<float> speed(5.5f);
    SecureValue<double> damage(125.75);
    SecureValue<int64_t> score(9223372036854775807LL);
    SecureValue<uint32_t> gold(4294967295U);
    SecureValue<bool> alive(true);
    SecureValue<char> rank('S');

    std::cout << "health: " << static_cast<int>(health) << "\n";
    std::cout << "speed: " << static_cast<float>(speed) << "\n";
    std::cout << "damage: " << static_cast<double>(damage) << "\n";
    std::cout << "score: " << static_cast<int64_t>(score) << "\n";
    std::cout << "gold: " << static_cast<uint32_t>(gold) << "\n";
    std::cout << "alive: " << (static_cast<bool>(alive) ? "true" : "false") << "\n";
    std::cout << "rank: " << static_cast<char>(rank) << "\n\n";

    health += 50;
    std::cout << "health +50: " << static_cast<int>(health) << "\n";

    health -= 25;
    std::cout << "health -25: " << static_cast<int>(health) << "\n";

    ++health;
    std::cout << "++health: " << static_cast<int>(health) << "\n";

    if (health > 100) {
        std::cout << "health > 100\n";
    }

    int normal = 12345;
    SecureValue<int> secure(12345);

    std::cout << "\nnormal int memory: 0x" << std::hex << *reinterpret_cast<uint32_t*>(&normal) << std::dec << "\n";
    std::cout << "secure int encrypted:\n";
    secure.debug();
    std::cout << "secure int decrypted: " << static_cast<int>(secure) << "\n";

    std::cout << "\nhealth encrypted:\n";
    health.debug();
    std::cout << "health decrypted: " << static_cast<int>(health) << "\n\n";

    std::cout << "=== running (press ctrl+c to exit) ===\n\n";

    int counter = 0;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        health += 10;
        gold += 100;
        counter++;

        std::cout << "[" << counter << "] health: " << static_cast<int>(health)
            << " | gold: " << static_cast<uint32_t>(gold) << "\n";

        if (counter % 5 == 0) {
            std::cout << "\nhealth encrypted:\n";
            health.debug();
            std::cout << "gold encrypted:\n";
            gold.debug();
            std::cout << "\n";
        }
    }

    return 0;
}
