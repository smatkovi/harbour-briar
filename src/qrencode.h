#ifndef QRENCODE_H
#define QRENCODE_H

// A QR encoder, only as much of the standard as this app needs: byte mode,
// error correction level M, versions 1 to 10 (up to 213 bytes). That covers
// a briar:// link with the addresses appended, and keeps the code small
// enough to read -- there is no QR library on either device.
//
// Shared by both front ends, like imageprep.h. The output is a matrix of
// booleans; whoever draws it decides how big a module is.

#include <algorithm>
#include <cstdlib>
#include <string>
#include <vector>

namespace qr {

struct Version {
    int ecPerBlock;
    int group1Blocks;
    int group1Data;
    int group2Blocks;
    int group2Data;
};

// Error correction level M, versions 1..10.
inline const Version *versionTable()
{
    static const Version table[10] = {
        { 10, 1, 16, 0,  0 },
        { 16, 1, 28, 0,  0 },
        { 26, 1, 44, 0,  0 },
        { 18, 2, 32, 0,  0 },
        { 24, 2, 43, 0,  0 },
        { 16, 4, 27, 0,  0 },
        { 18, 4, 31, 0,  0 },
        { 22, 2, 38, 2, 39 },
        { 22, 3, 36, 2, 37 },
        { 26, 4, 43, 1, 44 },
    };
    return table;
}

inline int dataCapacity(int version)
{
    const Version &v = versionTable()[version - 1];
    return v.group1Blocks * v.group1Data + v.group2Blocks * v.group2Data;
}

// --- Galois field 256, the one QR uses (primitive polynomial 0x11D) -------

inline const unsigned char *gfExp()
{
    static unsigned char exp[512];
    static unsigned char log[256];
    static bool ready = false;
    if (!ready) {
        int x = 1;
        for (int i = 0; i < 255; ++i) {
            exp[i] = (unsigned char)x;
            log[x] = (unsigned char)i;
            x <<= 1;
            if (x & 0x100)
                x ^= 0x11D;
        }
        for (int i = 255; i < 512; ++i)
            exp[i] = exp[i - 255];
        ready = true;
    }
    return exp;
}

inline const unsigned char *gfLog()
{
    static unsigned char log[256];
    static bool ready = false;
    if (!ready) {
        const unsigned char *exp = gfExp();
        for (int i = 0; i < 255; ++i)
            log[exp[i]] = (unsigned char)i;
        ready = true;
    }
    return log;
}

inline unsigned char gfMul(unsigned char a, unsigned char b)
{
    if (a == 0 || b == 0)
        return 0;
    return gfExp()[gfLog()[a] + gfLog()[b]];
}

// The generator polynomial for `count` error correction codewords.
inline std::vector<unsigned char> generator(int count)
{
    std::vector<unsigned char> poly;
    poly.push_back(1);
    for (int i = 0; i < count; ++i) {
        std::vector<unsigned char> next(poly.size() + 1, 0);
        for (int j = 0; j < (int)poly.size(); ++j) {
            next[j] = (unsigned char)(next[j] ^ gfMul(poly[j], 1));
            next[j + 1] = (unsigned char)(next[j + 1] ^ gfMul(poly[j], gfExp()[i]));
        }
        poly = next;
    }
    return poly;
}

inline std::string errorCorrection(const std::string &data, int count)
{
    std::vector<unsigned char> gen = generator(count);
    std::vector<unsigned char> remainder(count, 0);
    for (int i = 0; i < (int)data.size(); ++i) {
        unsigned char factor = (unsigned char)(data[i] ^ remainder[0]);
        for (int j = 0; j + 1 < (int)remainder.size(); ++j)
            remainder[j] = remainder[j + 1];
        remainder[remainder.size() - 1] = 0;
        for (int j = 0; j < count; ++j)
            remainder[j] = (unsigned char)(remainder[j] ^ gfMul(gen[j + 1], factor));
    }
    std::string out;
    for (int i = 0; i < count; ++i)
        out.push_back((char)remainder[i]);
    return out;
}

// --- Bit stream, matrix, masking ----------------------------------------

class BitStream
{
public:
    void append(int value, int bits)
    {
        for (int i = bits - 1; i >= 0; --i)
            m_bits.push_back((value >> i) & 1);
    }
    int size() const { return (int)m_bits.size(); }
    std::string toCodewords() const
    {
        std::string out;
        unsigned char current = 0;
        int filled = 0;
        for (int i = 0; i < m_bits.size(); ++i) {
            current = (unsigned char)((current << 1) | m_bits[i]);
            if (++filled == 8) {
                out.push_back((char)current);
                current = 0;
                filled = 0;
            }
        }
        if (filled > 0)
            out.push_back((char)(current << (8 - filled)));
        return out;
    }
private:
    std::vector<int> m_bits;
};

struct Matrix {
    int size;
    std::vector<char> module;   // 1 dark, 0 light
    std::vector<char> reserved; // 1 where a function pattern sits

    Matrix(int s) : size(s), module(s * s, 0), reserved(s * s, 0) {}
    bool dark(int x, int y) const { return module[y * size + x] != 0; }
    void set(int x, int y, bool value, bool isFunction)
    {
        module[y * size + x] = value ? 1 : 0;
        if (isFunction)
            reserved[y * size + x] = 1;
    }
    bool isReserved(int x, int y) const { return reserved[y * size + x] != 0; }
};

inline std::vector<int> alignmentCentres(int version)
{
    static const int centres[10][3] = {
        { -1, -1, -1 }, { 6, 18, -1 }, { 6, 22, -1 }, { 6, 26, -1 }, { 6, 30, -1 },
        { 6, 34, -1 },  { 6, 22, 38 }, { 6, 24, 42 }, { 6, 26, 46 }, { 6, 28, 50 },
    };
    std::vector<int> out;
    for (int i = 0; i < 3; ++i) {
        if (centres[version - 1][i] >= 0)
            out.push_back(centres[version - 1][i]);
    }
    return out;
}

inline void placeFinder(Matrix &m, int x0, int y0)
{
    for (int dy = -1; dy <= 7; ++dy) {
        for (int dx = -1; dx <= 7; ++dx) {
            int x = x0 + dx, y = y0 + dy;
            if (x < 0 || y < 0 || x >= m.size || y >= m.size)
                continue;
            bool dark = (dx >= 0 && dx <= 6 && (dy == 0 || dy == 6))
                     || (dy >= 0 && dy <= 6 && (dx == 0 || dx == 6))
                     || (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4);
            m.set(x, y, dark, true);
        }
    }
}

inline void placeFunctionPatterns(Matrix &m, int version)
{
    placeFinder(m, 0, 0);
    placeFinder(m, m.size - 7, 0);
    placeFinder(m, 0, m.size - 7);

    // Timing patterns
    for (int i = 8; i < m.size - 8; ++i) {
        bool dark = (i % 2) == 0;
        m.set(i, 6, dark, true);
        m.set(6, i, dark, true);
    }

    // Alignment patterns, except where they would sit on a finder
    std::vector<int> centres = alignmentCentres(version);
    for (int i = 0; i < (int)centres.size(); ++i) {
        for (int j = 0; j < (int)centres.size(); ++j) {
            int cx = centres[j], cy = centres[i];
            bool onFinder = (cx <= 8 && cy <= 8)
                         || (cx <= 8 && cy >= m.size - 9)
                         || (cx >= m.size - 9 && cy <= 8);
            if (onFinder)
                continue;
            for (int dy = -2; dy <= 2; ++dy) {
                for (int dx = -2; dx <= 2; ++dx) {
                    bool dark = (dx == -2 || dx == 2 || dy == -2 || dy == 2
                                 || (dx == 0 && dy == 0));
                    m.set(cx + dx, cy + dy, dark, true);
                }
            }
        }
    }

    // The one module that is always dark
    m.set(8, m.size - 8, true, true);

    // Reserve the format areas; the bits go in later.
    for (int i = 0; i <= 8; ++i) {
        if (i != 6) {
            m.set(i, 8, false, true);
            m.set(8, i, false, true);
        }
    }
    for (int i = 0; i < 8; ++i) {
        m.set(m.size - 1 - i, 8, false, true);
        if (i < 7)
            m.set(8, m.size - 1 - i, false, true);
    }

    // Version information, from version 7 on
    if (version >= 7) {
        int data = version;
        int rest = version << 12;
        for (int i = 0; i < 6; ++i) {
            if (rest & (1 << (17 - i)))
                rest ^= 0x1F25 << (5 - i);
        }
        int bits = (data << 12) | rest;
        for (int i = 0; i < 18; ++i) {
            bool dark = (bits >> i) & 1;
            int x = i / 3;
            int y = m.size - 11 + (i % 3);
            m.set(x, y, dark, true);
            m.set(y, x, dark, true);
        }
    }
}

inline bool maskBit(int mask, int x, int y)
{
    switch (mask) {
    case 0: return ((y + x) % 2) == 0;
    case 1: return (y % 2) == 0;
    case 2: return (x % 3) == 0;
    case 3: return ((y + x) % 3) == 0;
    case 4: return (((y / 2) + (x / 3)) % 2) == 0;
    case 5: return ((y * x) % 2 + (y * x) % 3) == 0;
    case 6: return (((y * x) % 2 + (y * x) % 3) % 2) == 0;
    default: return (((y + x) % 2 + (y * x) % 3) % 2) == 0;
    }
}

inline void placeFormat(Matrix &m, int mask)
{
    // Error correction level M is 00 in the format bits.
    int data = (0 << 3) | mask;
    int rest = data << 10;
    for (int i = 0; i < 5; ++i) {
        if (rest & (1 << (14 - i)))
            rest ^= 0x537 << (4 - i);
    }
    int bits = ((data << 10) | rest) ^ 0x5412;
    for (int i = 0; i <= 5; ++i)
        m.set(8, i, (bits >> i) & 1, true);
    m.set(8, 7, (bits >> 6) & 1, true);
    m.set(8, 8, (bits >> 7) & 1, true);
    m.set(7, 8, (bits >> 8) & 1, true);
    for (int i = 9; i < 15; ++i)
        m.set(14 - i, 8, (bits >> i) & 1, true);

    for (int i = 0; i < 8; ++i)
        m.set(m.size - 1 - i, 8, (bits >> i) & 1, true);
    for (int i = 8; i < 15; ++i)
        m.set(8, m.size - 15 + i, (bits >> i) & 1, true);
    m.set(8, m.size - 8, true, true);
}

inline int penalty(const Matrix &m)
{
    int score = 0;
    // Rule 1: runs of five or more
    for (int pass = 0; pass < 2; ++pass) {
        for (int a = 0; a < m.size; ++a) {
            int run = 1;
            bool last = pass ? m.dark(a, 0) : m.dark(0, a);
            for (int b = 1; b < m.size; ++b) {
                bool value = pass ? m.dark(a, b) : m.dark(b, a);
                if (value == last) {
                    ++run;
                } else {
                    if (run >= 5)
                        score += 3 + (run - 5);
                    run = 1;
                    last = value;
                }
            }
            if (run >= 5)
                score += 3 + (run - 5);
        }
    }
    // Rule 2: two by two blocks of one colour
    for (int y = 0; y + 1 < m.size; ++y) {
        for (int x = 0; x + 1 < m.size; ++x) {
            bool v = m.dark(x, y);
            if (v == m.dark(x + 1, y) && v == m.dark(x, y + 1) && v == m.dark(x + 1, y + 1))
                score += 3;
        }
    }
    // Rule 3: the finder-like pattern
    static const int pattern[7] = { 1, 0, 1, 1, 1, 0, 1 };
    for (int pass = 0; pass < 2; ++pass) {
        for (int a = 0; a < m.size; ++a) {
            for (int b = 0; b + 6 < m.size; ++b) {
                bool hit = true;
                for (int k = 0; k < 7 && hit; ++k) {
                    bool value = pass ? m.dark(a, b + k) : m.dark(b + k, a);
                    hit = (value == (pattern[k] != 0));
                }
                if (!hit)
                    continue;
                bool before = true, after = true;
                for (int k = 1; k <= 4; ++k) {
                    int p = b - k, q = b + 6 + k;
                    if (p >= 0 && (pass ? m.dark(a, p) : m.dark(p, a)))
                        before = false;
                    if (q < m.size && (pass ? m.dark(a, q) : m.dark(q, a)))
                        after = false;
                }
                if (before || after)
                    score += 40;
            }
        }
    }
    // Rule 4: how far the share of dark modules is from half
    int dark = 0;
    for (int i = 0; i < (int)m.module.size(); ++i)
        dark += m.module[i];
    int percent = dark * 100 / (int)m.module.size();
    int deviation = std::abs(percent - 50) / 5;
    score += deviation * 10;
    return score;
}

/// Encodes `text` and returns the matrix, or an empty one when the text is
/// longer than version 10 at level M can hold.
inline Matrix encode(const std::string &text)
{
    int version = 0;
    for (int v = 1; v <= 10; ++v) {
        int countBits = (v < 10) ? 8 : 16;
        int needed = 4 + countBits + (int)text.size() * 8;
        if (needed <= dataCapacity(v) * 8) {
            version = v;
            break;
        }
    }
    if (version == 0)
        return Matrix(0);

    const Version &spec = versionTable()[version - 1];
    const int capacity = dataCapacity(version);

    BitStream bits;
    bits.append(0x4, 4);                                  // byte mode
    bits.append((int)text.size(), version < 10 ? 8 : 16);
    for (int i = 0; i < (int)text.size(); ++i)
        bits.append((unsigned char)text[i], 8);
    int terminator = std::min(4, capacity * 8 - bits.size());
    bits.append(0, terminator);
    while (bits.size() % 8)
        bits.append(0, 1);
    std::string data = bits.toCodewords();
    bool pad = true;
    while ((int)data.size() < capacity) {
        data.push_back((char)(pad ? 0xEC : 0x11));
        pad = !pad;
    }

    // Split into blocks, add error correction to each, then interleave.
    std::vector<std::string> blocks, ecBlocks;
    int offset = 0;
    for (int i = 0; i < spec.group1Blocks; ++i) {
        blocks.push_back(data.substr(offset, spec.group1Data));
        offset += spec.group1Data;
    }
    for (int i = 0; i < spec.group2Blocks; ++i) {
        blocks.push_back(data.substr(offset, spec.group2Data));
        offset += spec.group2Data;
    }
    for (int i = 0; i < (int)blocks.size(); ++i)
        ecBlocks.push_back(errorCorrection(blocks[i], spec.ecPerBlock));

    std::string stream;
    int longest = std::max(spec.group1Data, spec.group2Data);
    for (int i = 0; i < longest; ++i) {
        for (int b = 0; b < (int)blocks.size(); ++b) {
            if (i < (int)blocks[b].size())
                stream.push_back(blocks[b][i]);
        }
    }
    for (int i = 0; i < spec.ecPerBlock; ++i) {
        for (int b = 0; b < (int)ecBlocks.size(); ++b)
            stream.push_back(ecBlocks[b][i]);
    }

    Matrix best(0);
    int bestScore = -1;
    for (int mask = 0; mask < 8; ++mask) {
        Matrix m(17 + 4 * version);
        placeFunctionPatterns(m, version);

        // The data, in the zigzag the standard prescribes, masked on the way.
        int bit = 0;
        bool upwards = true;
        for (int right = m.size - 1; right > 0; right -= 2) {
            if (right == 6)
                right = 5;  // the vertical timing pattern is skipped
            for (int step = 0; step < m.size; ++step) {
                int y = upwards ? m.size - 1 - step : step;
                for (int k = 0; k < 2; ++k) {
                    int x = right - k;
                    if (m.isReserved(x, y))
                        continue;
                    bool value = false;
                    if (bit < (int)stream.size() * 8) {
                        value = (stream[bit / 8] >> (7 - (bit % 8))) & 1;
                        ++bit;
                    } else {
                        ++bit;   // remainder bits stay light
                    }
                    if (maskBit(mask, x, y))
                        value = !value;
                    m.set(x, y, value, false);
                }
            }
            upwards = !upwards;
        }
        placeFormat(m, mask);
        int score = penalty(m);
        if (bestScore < 0 || score < bestScore) {
            bestScore = score;
            best = m;
        }
    }
    return best;
}

} // namespace qr

#endif
