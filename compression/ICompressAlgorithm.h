#ifndef ICOMPRESSALGORITHM_H
#define ICOMPRESSALGORITHM_H
#include <vector>
#include "types/Types.h"
namespace PFE
{
    namespace arc
    {
        class ICompressAlgorithm
        {
        public:
            virtual ~ICompressAlgorithm() {};
            virtual typ::u32 compress(const typ::ByteArray& dataToCompress, typ::ByteArray& compressedData) = 0;
            virtual typ::u32 decompress(typ::u32 originalDataSize, const typ::ByteArray& dataToDecompress, typ::ByteArray& decompressedData) = 0;
        };
    }

}



#endif // ICOMPRESSALGORITHM_H

