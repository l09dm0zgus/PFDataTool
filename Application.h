#ifndef APPLICATION_H
#define APPLICATION_H
#include "archive/Archive.h"

namespace PFE
{
    namespace app
    {
        class Application
        {
            public:
                int run(int argc,char *argv[]);
                ~Application();
            private:
                bool isArgumentCommand(char *string);
                void showHelp();
                arc::ArchiveWriter *archiveWriter{nullptr};
                arc::ArchiveReader *archiveReader{nullptr};
                const char* argumentCommand[7]{"--help","--create","--add",
                                        "--extract","--password","--encryption",
                                        "--compression"};
        };
    }
}


#endif // APPLICATION_H
