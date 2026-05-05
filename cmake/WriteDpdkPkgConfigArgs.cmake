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

set(ENV{PKG_CONFIG_PATH} "${DPDK_PKG_CONFIG_PATH}")

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
file(WRITE "${DPDK_COMPILE_ARGS_FILE}" "${compile_args}\n")
file(WRITE "${DPDK_LINK_ARGS_FILE}" "${link_args}\n")
