cmake_minimum_required(VERSION 3.5)

if (NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if (DEFINED ENV{VITASDK})
        set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
    else ()
        message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
    endif ()
endif ()

project(usbhostfs)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -std=gnu99 -nostdlib -O3 -Wno-incompatible-pointer-types -Wno-address-of-packed-member")

link_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(${PROJECT_NAME}
    usbhostfs.c
    host_driver.c
    hooks_io.c
)

target_compile_options(${PROJECT_NAME} PRIVATE
    -D__PSP2__ -D__KERNEL__ -D__USB__
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${PROJECT_NAME}
    taihenForKernel_stub
    SceSysmemForKernel_363_stub
    SceSysmemForDriver_stub
    SceSysclibForDriver_stub
    SceThreadmgrForDriver_stub
    SceIofilemgrForDriver_stub
    SceUdcdForDriver_stub
    SceCpuForDriver_stub
    SceDebugForDriver_stub
)

vita_create_self(${PROJECT_NAME}.skprx ${PROJECT_NAME} CONFIG ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}.yml)
