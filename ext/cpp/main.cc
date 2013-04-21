#include "cmdline.h"
#include "safest_ext.hh"

using namespace std;

int main(int argc, char const *argv[])
{
  gengetopt_args_info args;

  if (cmdline_parser(argc, (char **)argv,&args) != 0)
    exit(1);

  cs::CoordinateEngine engine = cs::CoordinateEngine::GetEngine();
  engine.start(args.port_arg);

  return 0;
}
