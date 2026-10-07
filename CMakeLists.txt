cmake_minimum_required(VERSION 3.21)
project(AardvarkHook VERSION 0.3.1 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "AardvarkHook requires x86 or x64 Windows.")
endif()

add_library(AardvarkHook STATIC src/hook.cpp src/decoder.cpp)
add_library(AardvarkHook::AardvarkHook ALIAS AardvarkHook)
target_compile_features(AardvarkHook PUBLIC cxx_std_17)
target_include_directories(AardvarkHook PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
if(MSVC)
    target_compile_options(AardvarkHook PRIVATE /W4 /permissive- /utf-8)
endif()


include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
install(TARGETS AardvarkHook EXPORT AardvarkHookTargets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT AardvarkHookTargets NAMESPACE AardvarkHook:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AardvarkHook)
configure_package_config_file(cmake/AardvarkHookConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/AardvarkHookConfig.cmake INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AardvarkHook)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/AardvarkHookConfigVersion.cmake COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/AardvarkHookConfig.cmake ${CMAKE_CURRENT_BINARY_DIR}/AardvarkHookConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AardvarkHook)
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/AardvarkHook)
