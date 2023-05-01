cmake_minimum_required(VERSION 3.22)
project(promo-echo LANGUAGES C)
include(ExternalProject)

# Distribution specific liburing may be quite outdated
# Therefore building known version of the library
ExternalProject_Add (
  liburing
  GIT_REPOSITORY https://github.com/axboe/liburing.git
  GIT_TAG liburing-2.3
  UPDATE_COMMAND ""
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND ./configure --prefix=<INSTALL_DIR>
  BUILD_COMMAND make -C src
  # In order to build with Ninja it is necessary to use VERSION 3.26 and uncomment the following line
  #INSTALL_BYPRODUCTS ${CMAKE_BINARY_DIR}/liburing-prefix/lib/liburing.a ${CMAKE_BINARY_DIR}/liburing-prefix/include/liburing.h ${CMAKE_BINARY_DIR}/liburing-prefix/include
  )

add_library(myliburing INTERFACE)# ${CMAKE_BINARY_DIR}/liburing-prefix/include/liburing.h
target_include_directories(myliburing INTERFACE ${CMAKE_BINARY_DIR}/liburing-prefix/include)
target_link_libraries(myliburing INTERFACE ${CMAKE_BINARY_DIR}/liburing-prefix/lib/liburing.a)

add_executable(promo-echo promo_echo.c)
target_link_libraries(promo-echo PRIVATE myliburing)
