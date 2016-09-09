CMAKE_MINIMUM_REQUIRED (VERSION 3.3)
PROJECT (sigh)

SET (MANPAGES asciidoc/sigh.8)
SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -pedantic")
SET (
    SOURCE_FILES
    src/common.h
    src/milter.h
    src/milter.cpp
    src/client.h
    src/client.cpp
    src/config.h
    src/config.cpp
    src/smime.h
    src/smime.cpp
    src/mapfile.h
    src/mapfile.cpp
)

FIND_PACKAGE (Threads)
FIND_PACKAGE (
    Boost COMPONENTS
    system
    filesystem
    program_options
    REQUIRED
)
FIND_PACKAGE (OpenSSL REQUIRED)

FIND_LIBRARY (milter_LIBRARIES milter)

INCLUDE_DIRECTORIES (
    ${Boost_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)
LINK_DIRECTORIES (
    ${Boost_LIBRARY_DIR}
)

ADD_EXECUTABLE (sigh ${SOURCE_FILES})

TARGET_COMPILE_DEFINITIONS (
    sigh PRIVATE
    _CB_ENVFROM
    _CB_HEADER
    _CB_EOH
    _CB_BODY
    _CB_EOM
)
TARGET_LINK_LIBRARIES (
    sigh
    ${CMAKE_THREAD_LIBS_INIT}
    ${milter_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${Boost_LIBRARIES}
)

INSTALL (
    FILES etc/sigh-example.cfg etc/mapfile-example.txt
    DESTINATION /etc/sigh
    COMPONENT config
)
INSTALL (
    FILES ${MANPAGES}
    DESTINATION share/man/man8
)
INSTALL (
    PROGRAMS sigh ${CMAKE_CURRENT_BINARY_DIR}/sigh
    DESTINATION sbin
)
