cmake_minimum_required(VERSION 3.10)

project(mapexec LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories(${PROJECT_SOURCE_DIR}/include)

# Récupérer tous les fichiers source du projet
file(GLOB SOURCES ${PROJECT_SOURCE_DIR}/src/*.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})

message(STATUS "Source files: ${SOURCES}")
message(STATUS "Include directory: ${PROJECT_SOURCE_DIR}/include")
