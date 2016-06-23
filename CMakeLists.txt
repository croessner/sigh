cmake_minimum_required(VERSION 3.3)
project(mymilter)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -pipe -std=c++14 -Wall -pedantic")
set(SOURCE_FILES src/milter.cpp src/client.h src/client.cpp src/milter.h src/config.h src/config.cpp src/smime.h src/smime.cpp src/util.h src/mapfile.h src/mapfile.cpp)

# Homebrew
if (APPLE)
    set(local_INCLUDE_DIR /usr/local/include)
    set(local_LIBRARY_DIR /usr/local/lib)
    set(openssl_INCLUDE_DIR /usr/local/opt/openssl/include)
    set(openssl_LIBARARYDIR /usr/local/opt/openssl/lib)
endif (APPLE)

find_package (Threads)
find_package(
        Boost COMPONENTS
        system
        filesystem
        program_options
        REQUIRED
)
find_library(milter_LIBRARIES milter)
find_library(mimetic_LIBRARIES mimetic)
find_library(crypto_LIBRARIES crypto)

include_directories(
        ${local_INCLUDE_DIR}
        ${Boost_INCLUDE_DIR}
        ${openssl_INCLUDE_DIR}
)
link_directories(
        ${local_LIBRARY_DIR}
        ${Boost_LIBRARY_DIR}
        ${openssl_LIBRARY_DIR}
)

add_executable(sigh ${SOURCE_FILES})

target_compile_definitions(
        sigh PRIVATE
        _CB_ENVFROM
        _CB_HEADER
        _CB_EOH
        _CB_BODY
        _CB_EOM
)
target_link_libraries (
        sigh
        ${CMAKE_THREAD_LIBS_INIT}
        ${milter_LIBRARIES}
        ${mimetic_LIBRARIES}
        ${crypto_LIBRARIES}
        ${Boost_LIBRARIES}
)
