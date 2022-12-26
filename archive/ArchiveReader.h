#ifndef ARCHIVEREADER_H
#define ARCHIVEREADER_H
#include <iostream>
#include <fstream>
#include <vector>
#include "compression/Compression.h"
#include "crypto/Cryptography.h"
#include "types/Types.h"
#include "FileSegments.h"
namespace PFE
{
    namespace arc
    {
        class ArchiveReader
        {
            public:
                ArchiveReader(const std::string &path, const std::string &password = "");
                ~ArchiveReader();
                typ::ByteArray getFile(const std::string &path);
                void extractAllFiles(const std::string &pathToExtract);
            private:
                std::string getFolder(const std::string &path);
                std::string getFileName(const std::string &path);
                void writeExtractedFile(const std::string &filePathInEntry,const std::string &pathToExctractedFile);
                void readHeader();
                void readTableHeader();
                void readFileEntrys();
                PFPackFileEntry readFileEntry();
                void setCompressAlgorithm();
                void setEncryptAlgorithm();
                typ::ByteArray getFile(const PFPackFileEntry &fileEntry);
                typ::ByteArray decompressFile(typ::u32 size,const typ::ByteArray &compressedFileData);
                typ::ByteArray decryptFile(const typ::ByteArray &encryptedFileData);
                void checkPasswordWithHash();

                std::string path;

                PFPackFileHeader header{0,0,0};
                PFPackTableHeader tableHeader{0,0};
                std::vector<PFPackFileEntry> fileEntrys;

                ICompressAlgorithm *compressionAlgorithm;

                crypt::IEncryptionAlgorithm *encryptionAlgorithm;
                std::string password{""};

                std::fstream archiveFile;
        };

    }
}


#endif // ARCHIVEREADER_H
