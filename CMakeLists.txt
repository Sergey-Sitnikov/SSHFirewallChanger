# changing the password/CMakeLists.txt

cmake_minimum_required(VERSION 3.10)
project(SSHFirewallChanger)

set(CMAKE_CXX_STANDARD 17)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

# --- QXlsx ---
set(QXLSX_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/QXlsx/QXlsx/header")
#set(QXLSX_LIBRARY_WIN "${CMAKE_SOURCE_DIR}/QXlsx/QXlsx/build/Release/QXlsxQt6.lib")
set(QXLSX_LIBRARY_WIN "${CMAKE_SOURCE_DIR}/QXlsx/QXlsx/build/libQXlsxQt6.a")
set(QXLSX_LIBRARY_UNIX "${CMAKE_SOURCE_DIR}/QXlsx/QXlsx/build_linux/libQXlsxQt6.a")

if(WIN32)
    if(EXISTS ${QXLSX_INCLUDE_DIR} AND EXISTS ${QXLSX_LIBRARY_WIN})
        message(STATUS "Found QXlsx: ${QXLSX_LIBRARY_WIN}")
        set(QXLSX_FOUND TRUE)
        set(QXLSX_LIBRARY ${QXLSX_LIBRARY_WIN})
    endif()
elseif(UNIX)
    if(EXISTS ${QXLSX_INCLUDE_DIR} AND EXISTS ${QXLSX_LIBRARY_UNIX})
        message(STATUS "Found QXlsx: ${QXLSX_LIBRARY_UNIX}")
        set(QXLSX_FOUND TRUE)
        set(QXLSX_LIBRARY ${QXLSX_LIBRARY_UNIX})
    endif()
endif()

# --- LibSSH ---
if(UNIX AND NOT WIN32)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBSSH REQUIRED IMPORTED_TARGET libssh)
else()
    find_path(LIBSSH_INCLUDE_DIR
        NAMES libssh/libssh.h
        PATHS ${LIBSSH_ROOT}/include ${CMAKE_PREFIX_PATH}/include
    )
    find_library(LIBSSH_LIBRARY
        NAMES ssh libssh
        PATHS ${LIBSSH_ROOT}/lib ${CMAKE_PREFIX_PATH}/lib
    )
    find_library(GCRYPT_LIBRARY
        NAMES gcrypt
        PATHS ${LIBSSH_ROOT}/lib ${CMAKE_PREFIX_PATH}/lib
    )
    find_library(GPG_ERROR_LIBRARY
        NAMES gpg-error
        PATHS ${LIBSSH_ROOT}/lib ${CMAKE_PREFIX_PATH}/lib
    )
    
    if(LIBSSH_INCLUDE_DIR AND LIBSSH_LIBRARY)
        set(LIBSSH_INCLUDE_DIRS ${LIBSSH_INCLUDE_DIR})
        message(STATUS "Found LibSSH: ${LIBSSH_LIBRARY}")
    endif()
endif()

find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(SSHFirewallChanger
    src/main.cpp
    src/SSHClient.cpp
    src/ThreadPool.h
)

set_target_properties(SSHFirewallChanger PROPERTIES AUTOMOC ON)

# Важно: LIBSSH_STATIC для статической линковки
if(WIN32)
    target_compile_definitions(SSHFirewallChanger PRIVATE LIBSSH_STATIC)
endif()

target_include_directories(SSHFirewallChanger PRIVATE ${LIBSSH_INCLUDE_DIRS})

target_link_libraries(SSHFirewallChanger
    Qt6::Widgets
    Threads::Threads
)

# QXlsx
if(QXLSX_FOUND)
    target_include_directories(SSHFirewallChanger PRIVATE ${QXLSX_INCLUDE_DIR})
    target_link_libraries(SSHFirewallChanger ${QXLSX_LIBRARY})
    target_compile_definitions(SSHFirewallChanger PRIVATE USE_QXLSX)
endif()

# LibSSH
if(TARGET PkgConfig::LIBSSH)
    target_link_libraries(SSHFirewallChanger PkgConfig::LIBSSH)
elseif(LIBSSH_LIBRARY)
    target_link_libraries(SSHFirewallChanger 
        ${LIBSSH_LIBRARY}
        ${GCRYPT_LIBRARY}
        ${GPG_ERROR_LIBRARY}
        ZLIB::ZLIB
        OpenSSL::Crypto
        OpenSSL::SSL
    )
    if(WIN32)
        target_link_libraries(SSHFirewallChanger iphlpapi ws2_32)
    endif()
endif()