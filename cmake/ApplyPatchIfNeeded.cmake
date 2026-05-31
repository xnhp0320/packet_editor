if(NOT DEFINED PATCH_EXECUTABLE)
    message(FATAL_ERROR "PATCH_EXECUTABLE is required")
endif()
if(NOT DEFINED PATCH_WORKING_DIR)
    message(FATAL_ERROR "PATCH_WORKING_DIR is required")
endif()
if(NOT DEFINED PATCH_FILE)
    message(FATAL_ERROR "PATCH_FILE is required")
endif()

# Check if patch is already applied by attempting a reverse dry-run.
execute_process(
    COMMAND ${PATCH_EXECUTABLE} -p1 -R --dry-run
    WORKING_DIRECTORY ${PATCH_WORKING_DIR}
    INPUT_FILE ${PATCH_FILE}
    RESULT_VARIABLE patch_already_applied
    OUTPUT_QUIET
    ERROR_QUIET
)

if(patch_already_applied EQUAL 0)
    message(STATUS "Patch already applied: ${PATCH_FILE}")
    return()
endif()

# Check if patch can be applied cleanly with a forward dry-run.
execute_process(
    COMMAND ${PATCH_EXECUTABLE} -p1 --dry-run
    WORKING_DIRECTORY ${PATCH_WORKING_DIR}
    INPUT_FILE ${PATCH_FILE}
    RESULT_VARIABLE patch_applies
    OUTPUT_QUIET
    ERROR_QUIET
)

if(NOT patch_applies EQUAL 0)
    message(FATAL_ERROR "Patch does not apply cleanly: ${PATCH_FILE}")
endif()

# Apply the patch for real.
execute_process(
    COMMAND ${PATCH_EXECUTABLE} -p1
    WORKING_DIRECTORY ${PATCH_WORKING_DIR}
    INPUT_FILE ${PATCH_FILE}
    RESULT_VARIABLE apply_result
)

if(NOT apply_result EQUAL 0)
    message(FATAL_ERROR "Failed to apply patch: ${PATCH_FILE}")
endif()
