if(NOT DEFINED PATCH_EXECUTABLE)
    message(FATAL_ERROR "PATCH_EXECUTABLE is required")
endif()
if(NOT DEFINED PATCH_WORKING_DIR)
    message(FATAL_ERROR "PATCH_WORKING_DIR is required")
endif()
if(NOT DEFINED PATCH_FILE)
    message(FATAL_ERROR "PATCH_FILE is required")
endif()

# Apply the patch with -N --forward for idempotency:
# - if the patch is already applied, it is silently skipped (exit 0)
# - if the patch has not been applied, it is applied normally
execute_process(
    COMMAND ${PATCH_EXECUTABLE} -p1 -N --forward
    WORKING_DIRECTORY ${PATCH_WORKING_DIR}
    INPUT_FILE ${PATCH_FILE}
    RESULT_VARIABLE apply_result
)

if(apply_result EQUAL 0)
    message(STATUS "Patch applied (or already present): ${PATCH_FILE}")
else()
    message(FATAL_ERROR "Failed to apply patch: ${PATCH_FILE}")
endif()
