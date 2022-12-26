#ifndef NOCOMPRESSION_H
#define NOCOMPRESSION_H
#include "ICompressAlgorithm.h"
namespace PFE
{
    namespace arc
    {
        class NoCompression : public ICompressAlgorithm
        {
            public:
                typ::u32 compress(const typ::ByteArray& dataToCompress, typ::ByteArray& compressedData) override;
                typ::u32 decompress(typ::u32 originalDataSize, const typ::ByteArray& dataToDecompress, typ::ByteArray& decompressedData) override;
        };

    }
}

#endif // NOCOMPRESSION_H
