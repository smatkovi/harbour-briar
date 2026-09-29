// Prueft meego/sha256.h gegen die Testvektoren aus FIPS 180-4.
//   g++ -I meego tools/sha256-probe.cpp -o /tmp/sha256-probe && /tmp/sha256-probe
#include "sha256.h"
#include <cstdio>
#include <cstring>
int main()
{
    struct { const char *ein; const char *soll; } faelle[] = {
        { "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" },
    };
    int fehler = 0;
    for (unsigned i = 0; i < sizeof(faelle) / sizeof(faelle[0]); ++i) {
        const std::string ist = sha256::hex(faelle[i].ein);
        if (ist != faelle[i].soll) { std::printf("FEHLER bei %u: %s\n", i, ist.c_str()); ++fehler; }
    }
    // Eine Million 'a', wie in FIPS 180-4.
    std::string viele(1000000, 'a');
    if (sha256::hex(viele) != "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") { std::puts("FEHLER bei 1e6 a"); ++fehler; }
    std::printf("%s\n", fehler ? "FEHLER" : "sha256 ok");
    return fehler;
}
