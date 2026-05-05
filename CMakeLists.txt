cmake_minimum_required(VERSION 3.20)
project(packet_editor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(PACKET_BUILD_DPDK "Build the bundled DPDK release and define DPDK::dpdk for future targets" ON)

include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

if(PACKET_BUILD_DPDK)
    include(ExternalProject)

    find_program(MESON_EXECUTABLE meson REQUIRED)
    find_program(GIT_EXECUTABLE git REQUIRED)
    find_program(PKG_CONFIG_EXECUTABLE NAMES pkg-config pkgconf REQUIRED)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)

    execute_process(
        COMMAND ${Python3_EXECUTABLE} -c "import elftools"
        RESULT_VARIABLE PACKET_PYELFTOOLS_RESULT
        OUTPUT_QUIET
        ERROR_QUIET
    )
    if(NOT PACKET_PYELFTOOLS_RESULT EQUAL 0)
        message(FATAL_ERROR "DPDK requires Python pyelftools. Install it with your distro package manager or pip.")
    endif()

    find_path(NUMA_INCLUDE_DIR numa.h)
    find_library(NUMA_LIBRARY numa)
    if(NOT NUMA_INCLUDE_DIR OR NOT NUMA_LIBRARY)
        message(FATAL_ERROR "DPDK requires libnuma development files. On Debian/Ubuntu, install libnuma-dev.")
    endif()

    set(DPDK_VERSION v25.11.2)
    set(DPDK_URL https://github.com/DPDK/dpdk/archive/refs/tags/${DPDK_VERSION}.tar.gz)
    set(DPDK_URL_HASH SHA256=009c69c6d1e715e38219d3bbff42188bf6eddc4fd85f0028126e3ca3d6989571)
    set(DPDK_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/dpdk-src)
    set(DPDK_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/dpdk-build)
    set(DPDK_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/dpdk-install)
    set(DPDK_COMPILE_ARGS_FILE ${CMAKE_CURRENT_BINARY_DIR}/dpdk_compile_args.rsp)
    set(DPDK_LINK_ARGS_FILE ${CMAKE_CURRENT_BINARY_DIR}/dpdk_link_args.rsp)
    set(DPDK_LIBPCAP_PATCH ${CMAKE_CURRENT_SOURCE_DIR}/patches/dpdk/0001-config-do-not-link-libpcap-when-net-pcap-is-disabled.patch)
    set(DPDK_PKG_CONFIG_PATH ${DPDK_INSTALL_DIR}/lib/x86_64-linux-gnu/pkgconfig:${DPDK_INSTALL_DIR}/lib/pkgconfig:${DPDK_INSTALL_DIR}/share/pkgconfig)
    set(DPDK_DISABLED_DRIVERS "bus/auxiliary,net/mlx5,net/af_packet,net/af_xdp,net/bnxt,net/e1000,net/ena,net/fm10k,net/i40e,net/ice,net/igc,net/ixgbe,net/virtio,net/vmxnet3,net/ark,net/atlantic,net/avp,net/axgbe,net/bnx2x,net/bond,net/cnxk,net/cxgbe,net/dpaa,net/dpaa2,net/enetc,net/enetfec,net/enic,net/failsafe,net/gve,net/hinic,net/hinic3,net/hns3,net/iavf,net/idpf,net/cpfl,net/ionic,net/mana,net/memif,net/mlx4,net/nbl,net/netvsc,net/nfp,net/ngbe,net/ntnic,net/null,net/octeontx,net/octeon_ep,net/pcap,net/pfe,net/qede,net/r8169,net/ring,net/rnp,net/sfc,net/softnic,net/thunderx,net/txgbe,net/vdev_netvsc,net/xsc,net/zxdh,crypto/*,compress/*,event/*,baseband/*,dma/*,raw/*,regex/*,vdpa/*,common/*")

    ExternalProject_Add(dpdk_external
        URL ${DPDK_URL}
        URL_HASH ${DPDK_URL_HASH}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        SOURCE_DIR ${DPDK_SOURCE_DIR}
        BINARY_DIR ${DPDK_BUILD_DIR}
        INSTALL_DIR ${DPDK_INSTALL_DIR}
        UPDATE_COMMAND ""
        PATCH_COMMAND
            ${CMAKE_COMMAND}
                -DGIT_EXECUTABLE=${GIT_EXECUTABLE}
                -DPATCH_WORKING_DIR=${DPDK_SOURCE_DIR}
                -DPATCH_FILE=${DPDK_LIBPCAP_PATCH}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ApplyPatchIfNeeded.cmake
        CONFIGURE_COMMAND
            ${MESON_EXECUTABLE} setup
                --prefix ${DPDK_INSTALL_DIR}
                ${DPDK_BUILD_DIR}
                ${DPDK_SOURCE_DIR}
                -Ddisable_drivers=${DPDK_DISABLED_DRIVERS}
                -Ddisable_libs=bpf,metrics,vhost,port
                -Ddisable_apps=*
        BUILD_COMMAND ${MESON_EXECUTABLE} compile -C ${DPDK_BUILD_DIR}
        INSTALL_COMMAND ${MESON_EXECUTABLE} install -C ${DPDK_BUILD_DIR}
        BUILD_BYPRODUCTS ${DPDK_INSTALL_DIR}/lib/pkgconfig/libdpdk.pc
    )

    add_custom_command(
        OUTPUT ${DPDK_COMPILE_ARGS_FILE} ${DPDK_LINK_ARGS_FILE}
        COMMAND
            ${CMAKE_COMMAND}
                -DPKG_CONFIG_EXECUTABLE=${PKG_CONFIG_EXECUTABLE}
                -DDPDK_PKG_CONFIG_PATH=${DPDK_PKG_CONFIG_PATH}
                -DDPDK_COMPILE_ARGS_FILE=${DPDK_COMPILE_ARGS_FILE}
                -DDPDK_LINK_ARGS_FILE=${DPDK_LINK_ARGS_FILE}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/WriteDpdkPkgConfigArgs.cmake
        DEPENDS dpdk_external
        VERBATIM
    )

    add_custom_target(dpdk_pkgconfig_args
        DEPENDS ${DPDK_COMPILE_ARGS_FILE} ${DPDK_LINK_ARGS_FILE}
    )

    add_library(dpdk INTERFACE)
    add_library(DPDK::dpdk ALIAS dpdk)
    add_dependencies(dpdk dpdk_pkgconfig_args)
    target_include_directories(dpdk INTERFACE ${DPDK_INSTALL_DIR}/include)
    target_compile_options(dpdk INTERFACE "SHELL:@${DPDK_COMPILE_ARGS_FILE}")
    target_link_options(dpdk INTERFACE "SHELL:@${DPDK_LINK_ARGS_FILE}")
endif()

add_library(packet
    src/lexer.cpp
    src/parser.cpp
    src/checker.cpp
    src/type_validator.cpp
    src/value.cpp
)

target_include_directories(packet PUBLIC include)

if(PACKET_BUILD_DPDK)
    add_library(packet_runtime
        src/runtime.cpp
    )
    target_link_libraries(packet_runtime PUBLIC packet DPDK::dpdk)

    add_executable(packet_dpdk_init apps/dpdk_init.cpp)
    target_link_libraries(packet_dpdk_init PRIVATE packet_runtime)

    add_executable(test_runtime tests/test_runtime.cpp)
    target_link_libraries(test_runtime packet_runtime gtest_main)
endif()

add_executable(test_lexer tests/test_lexer.cpp)
target_link_libraries(test_lexer packet gtest_main)

add_executable(test_parser tests/test_parser.cpp)
target_link_libraries(test_parser packet gtest_main)

add_executable(test_checker tests/test_checker.cpp)
target_link_libraries(test_checker packet gtest_main)

enable_testing()
add_test(NAME LexerTest  COMMAND test_lexer)
add_test(NAME ParserTest COMMAND test_parser)
add_test(NAME CheckerTest COMMAND test_checker)
if(PACKET_BUILD_DPDK)
    add_test(NAME RuntimeTest COMMAND test_runtime)
endif()
