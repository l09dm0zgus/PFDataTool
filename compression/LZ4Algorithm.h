#ifndef LZ4ALGORITHM_H
#define LZ4ALGORITHM_H

#include <vector>
#include "ICompressAlgorithm.h"
namespace PFE
{
    namespace arc
    {
        class LZ4Algorithm : public ICompressAlgorithm
        {
        public:
            typ::u32 compress(const typ::ByteArray& dataToCompress, typ::ByteArray& compressedData) override;
            typ::u32 decompress(typ::u32 originalDataSize, const typ::ByteArray& dataToDecompress, typ::ByteArray& decompressedData) override;
        };
    }

}


#endif //LZ4ALGORITHM_H
