cmake_minimum_required(VERSION 3.22)
project(promo-echo)
include(FetchContent)

# Distribution specific liburing may be quite outdated
# Therefore building known version of the library
FetchContent_Declare(
  liburing
  GIT_REPOSITORY https://github.com/axboe/liburing.git
  GIT_TAG liburing-2.3
  UPDATE_COMMAND ./configure
  )
FetchContent_MakeAvailable(liburing)

# liburing build system only builds shared libraries which is not convenient with no install
# Therefore building our own static version of the library
set(liburing_include_dir ${liburing_SOURCE_DIR}/src/include)
add_library(
  uring
  STATIC
  ${liburing_SOURCE_DIR}/src/setup.c
  ${liburing_SOURCE_DIR}/src/queue.c
  ${liburing_SOURCE_DIR}/src/register.c
  ${liburing_SOURCE_DIR}/src/syscall.c
  )

target_compile_options(uring PRIVATE -O3 -Wall -Wextra -fno-stack-protector -Wno-unused-parameter -Wno-sign-compare)
target_compile_definitions(uring PRIVATE _GNU_SOURCE LIBURING_INTERNAL)
target_include_directories(uring PUBLIC ${liburing_include_dir})

add_executable(promo-echo promo_echo.c)
target_link_libraries(promo-echo uring)
target_include_directories(promo-echo PRIVATE ${liburing_include_dir})
