cmake_minimum_required(VERSION 3.31)
project(VMP_UTIL)
set(CMAKE_CXX_STANDARD 17)


include(FetchContent)


set(ASMJIT_STATIC TRUE)


FetchContent_Declare(
        asmjit
        GIT_REPOSITORY https://github.com/asmjit/asmjit
        GIT_TAG master
)

FetchContent_Declare(
        minhook
        GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
        GIT_TAG master
)

FetchContent_Declare(
        zydis
        GIT_REPOSITORY https://github.com/zyantific/zydis
        GIT_TAG v4.1.0 # don't change this
)


FetchContent_MakeAvailable(asmjit minhook zydis)


add_library(VMP_UTIL SHARED VMP_UTIL/dllmain.cpp)


target_include_directories(VMP_UTIL PRIVATE VMP_UTIL)


target_link_libraries(VMP_UTIL PRIVATE asmjit minhook Zydis)
