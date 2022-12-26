#ifndef HASH_H
#define HASH_H
#include "types/Types.h"
#include <string>
#define HASHING_ROUNDS 32
namespace  PFE
{
    namespace crypt
    {
        constexpr typ::u32 polynomial = 0xEDB88320;
        inline typ::u32 crc32(const typ::u8 *data,typ::Size lenght,typ::u32 previousCRC = 0)
        {
            typ::u32 crc = ~previousCRC;
            while(lenght-- != 0)
            {
                crc ^= *data++;
                for(int i = 0;i<8;i++)
                {
                    crc = (crc >> 1)  ^ (-typ::u32(crc & 1) & polynomial);
                }
            }
            return ~crc;
        }
        inline typ::u32 hashString(const std::string &s)
        {
            typ::u32 hash{0};
            for(typ::i32 i{0}; i < HASHING_ROUNDS; i++)
            {
                hash = crypt::crc32((typ::u8*)s.c_str(),s.size(),hash);
            }
            return hash;
        }
    }
}
#endif // HASH_H
