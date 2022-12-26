#ifndef ARCHIVEWRITER_H
#define ARCHIVEWRITER_H
#include <filesystem>
#include <vector>
#include <fstream>
#include <string.h>
#include "FileSegments.h"
#include "types/Types.h"
#include "crypto/Cryptography.h"
#include "compression/Compression.h"

namespace PFE
{
    namespace arc
    {
        class ArchiveWriter
        {
            public:
                ArchiveWriter(const std::string &path,CompressionType compressionType,EncryptionType encryptionType,const std::string &password);
                ArchiveWriter(const std::string &path);
                ArchiveWriter(const std::string &path,CompressionType compressionType);
                ArchiveWriter(const std::string &path,EncryptionType encryptionType,const std::string &password);
                ~ArchiveWriter();
                void addFiles(const std::string &path);
            private:
                typ::u32 getDirectorySize(const std::string &path);
                typ::u32 getFileSize(const std::filesystem::path &path);
                typ::u32 getNumberOfFilesInDirectory(const std::string& path);
                void writeHeader();
                void writeTableHeader(const std::string &path);
                void writeFileEntry(const std::string &path, typ::u32 size, typ::u32 compressedSize);
                void setCompressAlgorithm();
                void setEncryptAlgorithm();
                typ::u32 readFileToArchive(const std::string &path, typ::ByteArray &readedFileData);
                typ::u32 compressFileToArchive(const typ::ByteArray &readedFileData,typ::ByteArray &compressedFileData);
                void writeCompressedFileToTemporaryFile(typ::ByteArray &compressedFileData);
                void readAndRemoveTemporaryFile();

                CompressionType compressionType{NO_COMPRESSION};
                ICompressAlgorithm *compressionAlgorithm{nullptr};

                EncryptionType encryptionType{NO_ENCRYPTION};
                crypt::IEncryptionAlgorithm *encryptionAlgorithm{nullptr};
                std::string password{""};

                std::fstream archiveFile;
                std::fstream temporaryFile;
                std::string temporaryFileName{".pfdata"};
                typ::u32 filesInDirectory{0};
                typ::u32 lastCompressedFileSize{0};
        };

    }
}


#endif // ARCHIVEWRITER_H
