if(NOT DEFINED DPDK_INSTALL_DIR)
    message(FATAL_ERROR "DPDK_INSTALL_DIR is required")
endif()
if(NOT DEFINED PACKET_DEPLOY_DIR)
    message(FATAL_ERROR "PACKET_DEPLOY_DIR is required")
endif()
if(NOT DEFINED STAMP_FILE)
    message(FATAL_ERROR "STAMP_FILE is required")
endif()

file(GLOB_RECURSE mlx5_glue_files
    LIST_DIRECTORIES false
    "${DPDK_INSTALL_DIR}/lib*/librte_common_mlx5_glue.so*"
)
if(NOT mlx5_glue_files)
    message(FATAL_ERROR "DPDK mlx5 glue library was not found under ${DPDK_INSTALL_DIR}")
endif()

file(MAKE_DIRECTORY "${PACKET_DEPLOY_DIR}")
foreach(glue_file IN LISTS mlx5_glue_files)
    file(COPY "${glue_file}" DESTINATION "${PACKET_DEPLOY_DIR}")
endforeach()
file(WRITE "${STAMP_FILE}" "${mlx5_glue_files}\n")
