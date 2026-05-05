if(NOT DEFINED GIT_EXECUTABLE)
    message(FATAL_ERROR "GIT_EXECUTABLE is required")
endif()
if(NOT DEFINED PATCH_WORKING_DIR)
    message(FATAL_ERROR "PATCH_WORKING_DIR is required")
endif()
if(NOT DEFINED PATCH_FILE)
    message(FATAL_ERROR "PATCH_FILE is required")
endif()

execute_process(
    COMMAND ${GIT_EXECUTABLE} apply --check ${PATCH_FILE}
    WORKING_DIRECTORY ${PATCH_WORKING_DIR}
    RESULT_VARIABLE patch_applies
    OUTPUT_QUIET
    ERROR_QUIET
)

if(patch_applies EQUAL 0)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} apply ${PATCH_FILE}
        WORKING_DIRECTORY ${PATCH_WORKING_DIR}
        RESULT_VARIABLE apply_result
    )
    if(NOT apply_result EQUAL 0)
        message(FATAL_ERROR "Failed to apply patch: ${PATCH_FILE}")
    endif()
    return()
endif()

execute_process(
    COMMAND ${GIT_EXECUTABLE} apply --reverse --check ${PATCH_FILE}
    WORKING_DIRECTORY ${PATCH_WORKING_DIR}
    RESULT_VARIABLE patch_already_applied
    OUTPUT_QUIET
    ERROR_QUIET
)

if(patch_already_applied EQUAL 0)
    message(STATUS "Patch already applied: ${PATCH_FILE}")
    return()
endif()

message(FATAL_ERROR "Patch does not apply cleanly: ${PATCH_FILE}")
