cmake_minimum_required(VERSION 3.16)
project(dosmnt C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)

add_executable(dosmnt
    src/main.c
    src/link.c
    ../common/src/rle.c
)

target_include_directories(dosmnt PRIVATE
    ${FUSE3_INCLUDE_DIRS}
    ../common/include
)

target_compile_options(dosmnt PRIVATE
    ${FUSE3_CFLAGS_OTHER}
)

target_link_libraries(dosmnt PRIVATE
    ${FUSE3_LIBRARIES}
    pthread
)
