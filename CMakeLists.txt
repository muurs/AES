cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

project("AES Implementation")

# Set some compiler flags
if (UNIX)
  set (CMAKE_CXX_FLAGS "-g3 -Wall -O2 -std=c++11")
endif ()

INCLUDE_DIRECTORIES( include )                           # Include Headers

file(GLOB sources ${PROJECT_SOURCE_DIR}/src/*.cpp)       # Include src Directory
add_executable(main.out ${sources})

