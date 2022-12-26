#include "Application.h"
#include <iostream>

int PFE::app::Application::run(int argc, char *argv[])
{
    switch (argc)
    {
    case 1:
        showHelp();
        break;
    case 2:
        showHelp();
        break;
    case 4:
        if(strcmp(argv[1],"--extract") == 0 && !isArgumentCommand(argv[2]) &&  !isArgumentCommand(argv[3]))
        {
            archiveReader = new arc::ArchiveReader(std::string(argv[2]));
            archiveReader->extractAllFiles(std::string(argv[3]));
        }
        else
        {
            showHelp();
        }
        break;
    case 5:
        if(strcmp(argv[1],"--create") == 0 && !isArgumentCommand(argv[2]) && strcmp(argv[3],"--add") == 0 && !isArgumentCommand(argv[4]))
        {
            archiveWriter = new arc::ArchiveWriter(std::string(argv[2]));
            archiveWriter->addFiles(std::string(argv[4]));

        }
        else
        {
            showHelp();
        }
        break;
    case 6:
        if(strcmp(argv[1],"--extract") == 0 && !isArgumentCommand(argv[2]) &&  !isArgumentCommand(argv[3]) && strcmp(argv[4],"--password") == 0 && !isArgumentCommand(argv[5]))
        {
            archiveReader = new arc::ArchiveReader(std::string(argv[2]),std::string(argv[5]));
            archiveReader->extractAllFiles(std::string(argv[3]));
        }
        else
        {
            showHelp();
        }
        break;
    case 7:
        if(strcmp(argv[1],"--create") == 0 && !isArgumentCommand(argv[2]) && strcmp(argv[3],"--add") == 0 && !isArgumentCommand(argv[4]) && strcmp(argv[5],"--compression") == 0 && !isArgumentCommand(argv[6]))
        {
            arc::CompressionType type;
            try
            {
                type = (arc::CompressionType)std::stoi(argv[6]);
            }
            catch (std::invalid_argument &exception)
            {
                std::cout << "Argument :" << argv[6] << " must be number!!!What: " << exception.what() << "\n";
                showHelp();
            }
            archiveWriter = new arc::ArchiveWriter(std::string(argv[2]),type);
            archiveWriter->addFiles(std::string(argv[4]));
        }
        else
        {
            showHelp();
        }
        break;
    case 9:
        if(strcmp(argv[1],"--create") == 0 && !isArgumentCommand(argv[2]) && strcmp(argv[3],"--add") == 0 && !isArgumentCommand(argv[4]) && strcmp(argv[5],"--encryption") == 0 && !isArgumentCommand(argv[6]) &&  strcmp(argv[7],"--password") == 0 && !isArgumentCommand(argv[8]))
        {
            arc::EncryptionType type;
            try
            {
                type = (arc::EncryptionType)std::stoi(argv[6]);
            }
            catch (std::invalid_argument &exception)
            {
                std::cout << "Argument :" << argv[6] << " must be number!!!What: " << exception.what() << "\n";
                showHelp();
            }
            archiveWriter = new arc::ArchiveWriter(std::string(argv[2]),type,std::string(argv[8]));
            archiveWriter->addFiles(std::string(argv[4]));
        }
        else
        {
            showHelp();
        }
        break;
    case 11:
        if(strcmp(argv[1],"--create") == 0 && !isArgumentCommand(argv[2]) && strcmp(argv[3],"--add") == 0 && !isArgumentCommand(argv[4]) && strcmp(argv[5],"--compression") == 0 && !isArgumentCommand(argv[6]) && strcmp(argv[7],"--encryption") == 0 && !isArgumentCommand(argv[8]) &&  strcmp(argv[9],"--password") == 0 && !isArgumentCommand(argv[10]))
        {
            arc::EncryptionType encryptionType;
            arc::CompressionType compressionType;

            try
            {
                encryptionType = (arc::EncryptionType)std::stoi(argv[8]);
                compressionType = (arc::CompressionType)std::stoi(argv[6]);
            }
            catch (std::invalid_argument &exception)
            {
                std::cout << "Argument must be number!!!What: " << exception.what() << "\n";
                showHelp();
            }
            archiveWriter = new arc::ArchiveWriter(std::string(argv[2]),compressionType,encryptionType,std::string(argv[10]));
            archiveWriter->addFiles(std::string(argv[4]));
        }
        else
        {
            showHelp();
        }
        break;
    default:
        showHelp();
        break;
    }
    return 0;
}

PFE::app::Application::~Application()
{
    if(archiveReader != nullptr)
    {
        delete archiveReader;
        archiveReader = nullptr;
    }

    if(archiveWriter != nullptr)
    {
        delete archiveWriter;
        archiveWriter = nullptr;
    }
}

bool PFE::app::Application::isArgumentCommand(char *string)
{
    for(auto command :argumentCommand)
    {
        if(strcmp(string,command) == 0)
        {
            return true;
        }
    }
    return false;
}

void PFE::app::Application::showHelp()
{
    std::cout << "--------------------------------------USAGE------------------------------------------\n";
    std::cout << "| --help - show this menu.                                                          |\n";
    std::cout << "| --create {archive name} - create archive.                                         |\n";
    std::cout << "| --extract {path to archive} {path where extract files} - extract files to folder. |\n";
    std::cout << "| --add {path to folder} - add folder to  archive.                                  |\n";
    std::cout << "| --password {password for archive} - set password for archive.                     |\n";
    std::cout << "| --encryption {0 - for no encryption , 1 - for AES256}.                            |\n";
    std::cout << "| --compression {0 - for no compression , 1  - for LZ4}.                            |\n";
    std::cout << "-------------------------------------------------------------------------------------\n";
}
