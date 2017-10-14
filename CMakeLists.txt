cmake_minimum_required(VERSION 3.8)
project(calc_src_mk)

set(CMAKE_CXX_STANDARD 11)

set(INCLUDE_MYSQL /usr/include/mysql)

set(LIBS crypto pthread ncurses config)
set(OCL_LIBS OpenCL)
set(MYSQL_LIBS mysqlclient)

set(SOURCE_FILES_MAIN
        main.cpp
        main.h
        queue_calc.h
        calc_thr.cpp
        calc_thr.h
        )
set(SOURCE_FILES_CONLY
        calc_data.cpp
        calc_data.h
        scl_thr.cpp
        scl_thr.h
        )

set(SOURCE_FILES_OCL
        cl_cl.cpp
        cl_cl.h)

set(SOURCE_FILES_SRV
        sql_thr.cpp
        sql_thr.h
        ssrv_thr.cpp
        ssrv_thr.h)
add_definitions(-Wno-deprecated-declarations)

set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g3")
set(CMAKE_CXX_FLAGS_RELEASE "-Ofast")
##set(CMAKE_CXX_FLAGS_RELEASE "-O3")

add_executable(cl_calc ${SOURCE_FILES_CONLY} ${SOURCE_FILES_MAIN})
target_link_libraries(cl_calc ${LIBS})

add_executable(cl_calc_ocl ${SOURCE_FILES_MAIN} ${SOURCE_FILES_CONLY} ${SOURCE_FILES_OCL})
target_compile_definitions(cl_calc_ocl PRIVATE OCL_CLIENT)
target_link_libraries(cl_calc_ocl ${LIBS} ${OCL_LIBS})

add_executable(srv_calc_ocl ${SOURCE_FILES_MAIN} ${SOURCE_FILES_CONLY} ${SOURCE_FILES_OCL} ${SOURCE_FILES_SRV})
target_include_directories(srv_calc_ocl PRIVATE ${INCLUDE_MYSQL})
target_compile_definitions(srv_calc_ocl PRIVATE SOCK_SERVER)
target_link_libraries(srv_calc_ocl ${LIBS} ${OCL_LIBS} ${MYSQL_LIBS})

add_executable(srv_only ${SOURCE_FILES_MAIN} ${SOURCE_FILES_SRV})
target_include_directories(srv_only PRIVATE ${INCLUDE_MYSQL})
target_compile_definitions(srv_only PRIVATE SOCK_SERVER PRIVATE ONLY_SERVER)
target_link_libraries(srv_only ${LIBS} ${MYSQL_LIBS})

