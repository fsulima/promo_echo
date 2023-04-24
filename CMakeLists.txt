cmake_minimum_required(VERSION 3.22)
project(promo-echo)
include(ExternalProject)

# Distribution specific liburing may be quite outdated
# Therefore building known version of the library
ExternalProject_Add (
  liburing
  GIT_REPOSITORY https://github.com/axboe/liburing.git
  GIT_TAG liburing-2.3
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND ./configure --prefix=<INSTALL_DIR>
  )

include_directories(${CMAKE_BINARY_DIR}/liburing-prefix/include)
add_executable(promo-echo promo_echo.c)
target_link_libraries(promo-echo ${CMAKE_BINARY_DIR}/liburing-prefix/lib/liburing.a)
