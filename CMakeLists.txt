cmake_minimum_required(VERSION 3.6)
project(ISA_project)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES Project/main.cpp Project/convert.cpp Project/convert.h Project/structures.h Project/structures.cpp)
add_executable(ISA_project ${SOURCE_FILES})