if(NOT DEFINED PKG_CONFIG_EXECUTABLE)
    message(FATAL_ERROR "PKG_CONFIG_EXECUTABLE is required")
endif()
if(NOT DEFINED DPDK_PKG_CONFIG_PATH)
    message(FATAL_ERROR "DPDK_PKG_CONFIG_PATH is required")
endif()
if(NOT DEFINED DPDK_COMPILE_ARGS_FILE)
    message(FATAL_ERROR "DPDK_COMPILE_ARGS_FILE is required")
endif()
if(NOT DEFINED DPDK_LINK_ARGS_FILE)
    message(FATAL_ERROR "DPDK_LINK_ARGS_FILE is required")
endif()

# Dynamically discover the architecture-specific pkgconfig directory
# (e.g. lib/x86_64-linux-gnu/pkgconfig or lib/aarch64-linux-gnu/pkgconfig).
# This must run at build time, after DPDK has been installed.
if(DEFINED DPDK_INSTALL_DIR)
    file(GLOB DPDK_ARCH_PKGCONFIG_DIRS LIST_DIRECTORIES true "${DPDK_INSTALL_DIR}/lib/*-linux-gnu/pkgconfig")
    if(DPDK_ARCH_PKGCONFIG_DIRS)
        list(GET DPDK_ARCH_PKGCONFIG_DIRS 0 DPDK_ARCH_PKGCONFIG_DIR)
        set(ENV{PKG_CONFIG_PATH} "${DPDK_ARCH_PKGCONFIG_DIR}:${DPDK_INSTALL_DIR}/lib/pkgconfig:${DPDK_INSTALL_DIR}/share/pkgconfig")
    else()
        set(ENV{PKG_CONFIG_PATH} "${DPDK_INSTALL_DIR}/lib/pkgconfig:${DPDK_INSTALL_DIR}/share/pkgconfig")
    endif()
else()
    set(ENV{PKG_CONFIG_PATH} "${DPDK_PKG_CONFIG_PATH}")
endif()

execute_process(
    COMMAND ${PKG_CONFIG_EXECUTABLE} --cflags libdpdk
    RESULT_VARIABLE compile_result
    OUTPUT_VARIABLE compile_args
    ERROR_VARIABLE compile_error
)
if(NOT compile_result EQUAL 0)
    message(FATAL_ERROR "Failed to query DPDK compile flags: ${compile_error}")
endif()

execute_process(
    COMMAND ${PKG_CONFIG_EXECUTABLE} --libs --static libdpdk
    RESULT_VARIABLE link_result
    OUTPUT_VARIABLE link_args
    ERROR_VARIABLE link_error
)
if(NOT link_result EQUAL 0)
    message(FATAL_ERROR "Failed to query DPDK link flags: ${link_error}")
endif()

string(STRIP "${compile_args}" compile_args)
string(STRIP "${link_args}" link_args)

if(link_args MATCHES "(^|[ \t\r\n])-lpcap([ \t\r\n]|$)" OR
   link_args MATCHES "(^|[ \t\r\n])-l:libpcap\\.a([ \t\r\n]|$)")
    message(FATAL_ERROR "DPDK static link flags unexpectedly reference libpcap: ${link_args}")
endif()

file(WRITE "${DPDK_COMPILE_ARGS_FILE}" "${compile_args}\n")
file(WRITE "${DPDK_LINK_ARGS_FILE}" "${link_args}\n")
