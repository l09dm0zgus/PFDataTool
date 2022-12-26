#ifndef FILESEGMENTS_H
#define FILESEGMENTS_H
#define VERSION 0xC09D530
#define MAXIMAL_LENGHT_OF_PATH 256
#include <iostream>
#include "types/Types.h"
namespace PFE
{
    namespace  arc
    {
        enum CompressionType
        {
            NO_COMPRESSION,
            LZ4,
        };

        enum EncryptionType
        {
            NO_ENCRYPTION,
            AES256,
        };

        #pragma pack(push,1)
        struct PFPackFileHeader
        {
            typ::u32 version{0};
            typ::u8 compression{0};
            typ::u8 encryption{0};
            typ::u32 passwordHash{0};
        };

        struct PFPackTableHeader
        {
            typ::u32 numberOfFiles{0};
            typ::u32 sizeOfDirectory{0};
        };

        struct PFPackFileEntry
        {
            char pathToFile[MAXIMAL_LENGHT_OF_PATH]{0};
            typ::u32 offset{0};
            typ::u32 compressedSize{0};
            typ::u32 size{0};
        };
        #pragma pack(pop)

       inline std::ostream& operator<<(std::ostream &os,const PFE::arc::PFPackFileHeader &header)
        {
            os << "Version : " << header.version << "\nCompresion : " << (typ::u32) header.compression << " \nEncryption : " << (typ::u32)header.encryption << " \n";
            return os;
        }

        inline std::ostream& operator<<(std::ostream &os,const PFE::arc::PFPackTableHeader &tableHeader)
        {
           os << "Files in directory : " << tableHeader.numberOfFiles << "\nDirectory size : " << tableHeader.sizeOfDirectory << " \n";
           return os;
        }

        inline std::ostream& operator<<(std::ostream &os,const PFE::arc::PFPackFileEntry &fileEntry)
        {
           os << "Path to file: " << fileEntry.pathToFile << "\nFile offset : " << fileEntry.offset << " \nCompressed size : " << fileEntry.compressedSize << " \nSize : " << fileEntry.size << " \n";
           return os;
        }

    }

}

#endif // FILESEGMENTS_H
