cmake_minimum_required(VERSION 3.16)
project(dosmnt_host C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)

add_executable(dosmnt_host
    src/main.c
    src/link.c
)

target_include_directories(dosmnt_host PRIVATE
    ${FUSE3_INCLUDE_DIRS}
    ../common/include
)

target_compile_options(dosmnt_host PRIVATE
    ${FUSE3_CFLAGS_OTHER}
)

target_link_libraries(dosmnt_host PRIVATE
    ${FUSE3_LIBRARIES}
    pthread
)
