cmake_minimum_required(VERSION 3.20)
project(packet_editor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_library(packet
    src/lexer.cpp
    src/parser.cpp
    src/checker.cpp
    src/type_validator.cpp
    src/value.cpp
)

target_include_directories(packet PUBLIC include)

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
