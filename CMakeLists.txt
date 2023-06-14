cmake_minimum_required(VERSION 3.10)

project(isis-mocker CXX)

set(MAJOR_VERSION 1)
set(MINOR_VERSION 0)
set(PATCH_VERSION 0)

set(PROJECT_VERSION ${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION})
project(isis-mocker VERSION ${PROJECT_VERSION})

configure_file(version.h.in include/version.h)

add_executable(isis-mocker
    main.cpp
)
add_executable(tests
    tests.cpp
)

add_executable(isis-mocker-debug
    main.cpp
)
add_library(isis-mocker-version get_version.cpp)
target_include_directories(isis-mocker-version PRIVATE include)


target_include_directories(isis-mocker PRIVATE include)
set_target_properties(isis-mocker PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads)
set(Boost_USE_STATIC_LIBS   ON)
find_package(Boost COMPONENTS thread program_options REQUIRED)
target_link_libraries(isis-mocker Threads::Threads  Boost::thread Boost::program_options isis-mocker-version)


target_include_directories(isis-mocker-debug PRIVATE include)
set_target_properties(isis-mocker-debug PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
target_link_libraries(isis-mocker-debug Threads::Threads Boost::thread Boost::program_options isis-mocker-version)


target_compile_options(isis-mocker PRIVATE -Werror)
set_target_properties(isis-mocker PROPERTIES LINK_FLAGS_RELEASE -s)
target_compile_options(isis-mocker-debug PRIVATE -g -Werror)
target_compile_definitions(isis-mocker-debug PRIVATE DEBUG)
target_include_directories(tests PRIVATE include)
target_include_directories(isis-mocker-version PRIVATE include)
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
target_link_libraries(tests gmock gmock_main gtest pthread)
set_target_properties(tests PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)


enable_testing()
install(TARGETS isis-mocker RUNTIME DESTINATION bin)

add_test(NAME GTest COMMAND tests)


set(CPACK_GENERATOR DEB)

set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")

set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

set(CPACK_PACKAGE_CONTACT achursin1986@gmail.com)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS YES)

include(CPack)


