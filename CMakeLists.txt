cmake_minimum_required(VERSION 3.3)
project(mymilter)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall")
set(SOURCE_FILES src/milter.cpp src/client.h src/client.cpp src/milter.h src/config.h src/config.cpp)

set(local_INCLUDE_DIR /usr/local/include)
set(local_LIBRARY_DIR /usr/local/lib)

find_package (Threads)
find_package(
        Boost COMPONENTS
        system
        filesystem
        program_options
        REQUIRED
)
find_library(libmilter_LIBRARIES milter)

include_directories(${local_INCLUDE_DIR} ${Boost_INCLUDE_DIR})
link_directories(${local_LIBRARY_DIR} ${Boost_LIBRARY_DIR})

add_executable(mymilter ${SOURCE_FILES})

target_compile_definitions(
        mymilter PRIVATE
        _CB_ENVFROM
        _CB_HEADER
        _CB_EOH
        _CB_BODY
        _CB_EOM
)
target_link_libraries (
        mymilter
        ${CMAKE_THREAD_LIBS_INIT}
        ${libmilter_LIBRARIES}
        ${Boost_LIBRARIES}
)
