#ifndef TYPES_H
#define TYPES_H
#include <cstdint>
#include <vector>
namespace  PFE
{
    namespace typ
    {
        typedef char i8;
        typedef unsigned char u8;
        typedef short i16;
        typedef unsigned short u16;
        typedef int i32;
        typedef unsigned int u32;
        typedef long i64;
        typedef unsigned long u64;
        typedef float f32;
        typedef double f64;
        typedef std::size_t Size;
        typedef std::vector<u8> ByteArray;
    }
}
#endif // TYPES_H
