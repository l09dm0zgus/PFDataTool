#include <iostream>
#include <fstream>
#include "Application.h"

using namespace std;
int main(int argc, char *argv[])
{
    PFE::app::Application app;
    return app.run(argc,argv);
}
