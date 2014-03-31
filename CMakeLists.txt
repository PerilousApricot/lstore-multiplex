cmake_minimum_required(VERSION 2.8)
# make a project
project(gridftp-lfs C)

# Set some cmake defaults
set(CMAKE_BUILD_TYPE "Debug")

set(CMAKE_INCLUDE_CURRENT_DIR on)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

# get dependancies
find_package(ZMQ REQUIRED)
find_package(CZMQ REQUIRED)
find_package(FUSE REQUIRED)
find_package(XATTR REQUIRED)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_REQUIRED_FLAGS} -O0 -Wall -g -DHAVE_CONFIG_H -DLINUX=2 -D_REENTRANT -D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 ${XATTR_FOUND}" )
set(CMAKE_C_FLAGS_RELEASE "-O ${CMAKE_REQUIRED_FLAGS} -DHAVE_CONFIG_H -DLINUX=2 -D_REENTRANT -D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 ${XATTR_FOUND}" )


include_directories(${FUSE_INCLUDE_DIR} ${CZMQ_INCLUDE_DIR} ${XATTR_INCLUDE_DIR})
SET(LIBS ${LIBS} ${FUSE_LIBRARY} pthread m )
message(STATUS "GOT LIBS ${LIBS}")
add_executable(fuse_multiplex fuse.c statsd-client.c)
target_link_libraries(fuse_multiplex ${LIBS})
