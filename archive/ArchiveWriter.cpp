#include "ArchiveWriter.h"
#include <iostream>
#include <iterator>

PFE::arc::ArchiveWriter::ArchiveWriter(const std::string &path,CompressionType compressionType,EncryptionType encryptionType,const std::string &password):ArchiveWriter(path,encryptionType,password)
{
    this->compressionType = compressionType;
    setCompressAlgorithm();
    setEncryptAlgorithm();
}

PFE::arc::ArchiveWriter::ArchiveWriter(const std::string &path, CompressionType compressionType):ArchiveWriter(path)
{
    this->compressionType = compressionType;
    setCompressAlgorithm();
    setEncryptAlgorithm();
}

PFE::arc::ArchiveWriter::ArchiveWriter(const std::string &path, EncryptionType encryptionType, const std::string &password) : ArchiveWriter(path)
{
    this->encryptionType = encryptionType;
    this->password = password;
    setCompressAlgorithm();
    setEncryptAlgorithm();

}

PFE::arc::ArchiveWriter::~ArchiveWriter()
{
    delete compressionAlgorithm;
    compressionAlgorithm = nullptr;

    delete encryptionAlgorithm;
    encryptionAlgorithm = nullptr;
}


PFE::arc::ArchiveWriter::ArchiveWriter(const std::string &path)
{
   archiveFile.exceptions(std::fstream::badbit);
   try
   {
        archiveFile.open(path,std::ios::out | std::ios::binary);
   }
   catch (const std::ifstream::failure& exception)
   {
       std::cout << "Error: Failed to open " << path << ".What:" << exception.what() << std::endl;
       exit(-1488);
   }

   temporaryFile.exceptions(std::fstream::badbit);
   try
   {
       temporaryFile.open(temporaryFileName, std::ios::out| std::ios::binary);
   }
   catch (const std::ifstream::failure& exception)
   {
       std::cout << "Error: Failed to open temporary file.What:" << exception.what() << std::endl;
       exit(-1488);
   }
   setCompressAlgorithm();
   setEncryptAlgorithm();
}


void PFE::arc::ArchiveWriter::addFiles(const std::string &path)
{
    writeHeader();
    writeTableHeader(path);
    try
    {
        for (const auto& pathToFile : std::filesystem::recursive_directory_iterator(path))
        {
            if (pathToFile.is_regular_file())
            {
                typ::ByteArray readedFileData,compressedFileData,encryptedFileData;
                typ::u32 size{0},compressedSize{0};
                size = readFileToArchive(pathToFile.path().string(),readedFileData);
                std::cout << "Encrypting file data...\n";
                size = encryptionAlgorithm->encrypt(typ::ByteArray(password.begin(),password.end()),readedFileData,encryptedFileData);
                compressedSize = compressFileToArchive(encryptedFileData,compressedFileData);
                writeFileEntry(pathToFile.path().string(),size,compressedSize);
                writeCompressedFileToTemporaryFile(compressedFileData);
            }
        }
        readAndRemoveTemporaryFile();
        archiveFile.close();
    }
    catch (const std::filesystem::filesystem_error& exception)
    {
        std::cout << "Error: " << exception.what() << "\n";
        exit(-1488);
    }
}

PFE::typ::u32 PFE::arc::ArchiveWriter::getDirectorySize(const std::string &path)
{
    typ::u32 directorySize = 0;
    try
    {
        for (const auto& pathToFile : std::filesystem::recursive_directory_iterator(path))
        {
            if (pathToFile.is_regular_file())
            {
                directorySize += getFileSize(pathToFile);
            }
        }
    }
    catch (const std::filesystem::filesystem_error& exception)
    {
        std::cout << "Error: " << exception.what() << "\n";
        exit(-1488);
    }
    return directorySize;
}

PFE::typ::u32 PFE::arc::ArchiveWriter::getFileSize(const std::filesystem::path &path)
{
    return std::filesystem::file_size(path);
}

PFE::typ::u32 PFE::arc::ArchiveWriter::getNumberOfFilesInDirectory(const std::string& path)
{
    typ::u32 filesInDirectory = 0;
    try
    {
        for (const auto& pathToFile : std::filesystem::recursive_directory_iterator(path))
        {
            if (pathToFile.is_regular_file())
            {
                ++filesInDirectory;
            }
        }
    }
    catch (const std::filesystem::filesystem_error& exception)
    {
        std::cout << "Error: " << exception.what() << "\n";
        exit(-1488);
    }
    return filesInDirectory;
}

void PFE::arc::ArchiveWriter::writeHeader()
{
    PFPackFileHeader header;
    header.version = VERSION;
    header.compression = compressionType;
    header.encryption = encryptionType;
    header.passwordHash = crypt::hashString(password);
    std::cout << "Writting file header...\n";
    archiveFile.write((char*)&header,sizeof(header));
}

void PFE::arc::ArchiveWriter::writeTableHeader(const std::string &path)
{
    PFPackTableHeader tableHeader;
    filesInDirectory = getNumberOfFilesInDirectory(path);
    tableHeader.numberOfFiles = filesInDirectory;
    tableHeader.sizeOfDirectory = getDirectorySize(path);
    std::cout << "Writting table header...\n";
    archiveFile.write((char*)&tableHeader,sizeof(tableHeader));
}

void PFE::arc::ArchiveWriter::writeFileEntry(const std::string &path, typ::u32 size, typ::u32 compressedSize)
{
    PFPackFileEntry fileEntry;
    strncpy(fileEntry.pathToFile,path.c_str(),path.size());
    fileEntry.size = size;
    fileEntry.compressedSize = compressedSize;
    fileEntry.offset = sizeof(PFPackFileHeader) + sizeof(PFPackTableHeader) + (sizeof(PFPackFileEntry) * filesInDirectory) + lastCompressedFileSize;
    lastCompressedFileSize = compressedSize;
    std::cout << "Writting file entry... \n";
    archiveFile.write((char*)&fileEntry,sizeof(PFPackFileEntry));
}

void PFE::arc::ArchiveWriter::setCompressAlgorithm()
{
    switch (compressionType)
    {
    case NO_COMPRESSION:
        compressionAlgorithm = new NoCompression();
        break;
    case LZ4:
        compressionAlgorithm = new LZ4Algorithm();
        break;
    default:
        compressionAlgorithm = nullptr;
        break;
    }
}

void PFE::arc::ArchiveWriter::setEncryptAlgorithm()
{
    switch (encryptionType)
    {
    case NO_ENCRYPTION:
        encryptionAlgorithm = new crypt::NoEncryption();
        break;
    case AES256:
        encryptionAlgorithm = new crypt::AES256();
        break;
    default:
        encryptionAlgorithm = nullptr;
        break;
    }
}

PFE::typ::u32 PFE::arc::ArchiveWriter::readFileToArchive(const std::string &path,typ::ByteArray &readedFileData)
{
    typ::u32 size;
    std::fstream fileToRead;
    std::cout << "Reading " << path << " to archive...\n";
    fileToRead.exceptions(std::ifstream::badbit);
    try
    {
        fileToRead.open(path, std::ios::in);
    }
    catch (const std::ifstream::failure& exception)
    {
        std::cout << "Error: Failed to read file for compression.What:" << exception.what() << std::endl;
        exit(-1488);
    }

    //get file size
    fileToRead.seekg(0, std::ios::end);
    size = fileToRead.tellg();
    fileToRead.seekg(0, std::ios::beg);
    char fileContent[size];
    readedFileData.reserve(size);
    fileToRead.read(fileContent,size);
    readedFileData.assign(fileContent,fileContent+size);
    return readedFileData.size();
}

PFE::

typ::u32 PFE::arc::ArchiveWriter::compressFileToArchive(const typ::ByteArray &readedFileData, typ::ByteArray &compressedFileData)
{
    typ::u32 compressedSize = 0;
    std::cout << "Compressing file...\n";
    if (readedFileData.size() > 0)
    {
        try
        {
            compressedSize = compressionAlgorithm->compress(readedFileData, compressedFileData);
        }
        catch (const char* exception)
        {
            std::cout << "Error: " << exception << "\n";
            exit(-1488);
        }
    }
    return compressedSize;
}

void PFE::arc::ArchiveWriter::writeCompressedFileToTemporaryFile(typ::ByteArray &compressedFileData)
{
    std::cout << "Write compressed data to temporary file...\n";
    temporaryFile.write((char*)&compressedFileData[0],compressedFileData.size());
}

void PFE::arc::ArchiveWriter::readAndRemoveTemporaryFile()
{
    temporaryFile.close();
    try
    {
        temporaryFile.open(temporaryFileName, std::ios::in| std::ios::binary);
    }
    catch (const std::ifstream::failure& exception)
    {
        std::cout << "Error: Failed to open temporary file.What:" << exception.what() << std::endl;
        exit(-1488);
    }
    std::cout << "Read temporary file to archive...\n";
    archiveFile << temporaryFile.rdbuf();
    temporaryFile.close();
    std::filesystem::remove(temporaryFileName);
}

