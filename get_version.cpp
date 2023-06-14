#include <string>
#include "get_version.h"

#include "version.h"

std::string version() {

    int Major{}, Minor{}, Patch{}, Beta{};
    #ifdef PROJECT_VERSION_MAJOR
    Major = PROJECT_VERSION_MAJOR;
    #endif

    #ifdef PROJECT_VERSION_MINOR
    Minor = PROJECT_VERSION_MINOR;
    #endif

    #ifdef PROJECT_VERSION_PATCH
    Patch = PROJECT_VERSION_PATCH;
    #endif

    return "v" + std::to_string(Major) + "." + std::to_string(Minor) + "." +  std::to_string(Patch);
}
