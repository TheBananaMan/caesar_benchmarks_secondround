CMAKE_MINIMUM_REQUIRED(VERSION 2.8.1)

set(CMAKE_VERBOSE_MAKEFILE 1)

#SET(CMAKE_C_COMPILER "/usr/local/bin/gcc-4.9")
#SET(CMAKE_C_COMPILER "~/arm-cs-tools/bin/arm-none-eabi-gcc")

# set project name
PROJECT(CAESAR_BENCHMARKS)

SET(DEFAULT_BUILD_TYPE Debug)
#SET(CMAKE_BUILD_TYPE Release)

SET(DEFAULT_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/out/static")
SET(DEFAULT_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/out/lib")
SET(DEFAULT_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/out/bin")

SET(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
INCLUDE(setDefaultSettings)
#INCLUDE(setPlatformAndCompilerFlags)

SET(CMAKE_C_FLAGS "-Ofast -fno-stack-protector -march=native -std=gnu11 -I ${PROJECT_SOURCE_DIR}/include")

MESSAGE(STATUS "${CMAKE_C_FLAGS}")

FIND_LIBRARY(LCRYPTO ssl)
IF(NOT LCRYPTO)
	MESSAGE(FATAL_ERROR "ssl library not found")
ENDIF()

MACRO(SUBDIRLIST result curdir)
	FILE(GLOB children RELATIVE ${curdir} ${curdir}/*)
	SET(dirlist "")
	FOREACH(child ${children})
		IF(IS_DIRECTORY ${curdir}/${child})
			LIST(APPEND dirlist ${child})
		ENDIF()
	ENDFOREACH()
	SET(${result} ${dirlist})
ENDMACRO()

#------------------------------------------------------------------------------
# Project config
#------------------------------------------------------------------------------

SET(CIPHER_PATH "${CMAKE_SOURCE_DIR}/crypto_aead")
SUBDIRLIST(LISTOFCIPHERS ${CIPHER_PATH})

# Add target for testing
#-----------------------------------------

FOREACH(CIPHER ${LISTOFCIPHERS})
#	MESSAGE(STATUS "CIPHER:    ${CIPHER_PATH}/${CIPHER}")
	SUBDIRLIST(OPTIMIZATIONS "${CIPHER_PATH}/${CIPHER}")
	FOREACH(OPT ${OPTIMIZATIONS})
		SET(TargetName "testing_${CIPHER}_${OPT}")
#		MESSAGE(STATUS "targetname    ${TargetName}")
		FILE(GLOB_RECURSE TestingSources "testing/*.c" "${CIPHER_PATH}/${CIPHER}/${OPT}/*.c")
#		MESSAGE(STATUS "testing sources:    ${TestingSources}")
		ADD_EXECUTABLE( "${TargetName}" ${TestingSources} )
		ADD_DEPENDENCIES("testing_${CIPHER}_${OPT}" "${TargetName}")

		# link against the corresponding framework library
		TARGET_LINK_LIBRARIES( "${TargetName}" "m" "-lcrypto")
		# add preprocessor define for the target
		SET_TARGET_PROPERTIES("${TargetName}" PROPERTIES COMPILE_FLAGS "-D cipher_${CIPHER} -D cipher_opt_${OPT} -DCAESAR_CIPHER=${CIPHER} -DCAESAR_OPT=${OPT} -I ${CIPHER_PATH}/${CIPHER}/${OPT} ")
	ENDFOREACH()
ENDFOREACH()

# Add target for timing
#-----------------------------------------

FOREACH(CIPHER ${LISTOFCIPHERS})
#	MESSAGE(STATUS "CIPHER:    ${CIPHER_PATH}/${CIPHER}")
	SUBDIRLIST(OPTIMIZATIONS "${CIPHER_PATH}/${CIPHER}")
	FOREACH(OPT ${OPTIMIZATIONS})
		SET(TargetName "timing_${CIPHER}_${OPT}")
#		MESSAGE(STATUS "targetname    ${TargetName}")
		FILE(GLOB_RECURSE TimingSources "timing/*.c" "${CIPHER_PATH}/${CIPHER}/${OPT}/*.c")
#		MESSAGE(STATUS "timing sources:    ${TimingSources}")
		ADD_EXECUTABLE( "${TargetName}" ${TimingSources} )
		ADD_DEPENDENCIES("timing_${CIPHER}_${OPT}" "${TargetName}")

		# link against the corresponding framework library
		TARGET_LINK_LIBRARIES( "${TargetName}" "m" "-lcrypto")
		# add preprocessor define for the target
		SET_TARGET_PROPERTIES("${TargetName}" PROPERTIES COMPILE_FLAGS "-D cipher_${CIPHER} -D cipher_opt_${OPT} -DCAESAR_CIPHER=${CIPHER} -DCAESAR_OPT=${OPT} -I ${CIPHER_PATH}/${CIPHER}/${OPT} ")
	ENDFOREACH()
ENDFOREACH()


MESSAGE(STATUS "------------------------------------------------------------------------------")
MESSAGE(STATUS "List of ciphers:")
FOREACH(CIPHER ${LISTOFCIPHERS})
	MESSAGE(STATUS "CIPHER:		${CIPHER}")
	SUBDIRLIST(OPTIMIZATIONS "${CIPHER_PATH}/${CIPHER}")
	FOREACH(OPT ${OPTIMIZATIONS})
		MESSAGE(STATUS "	OPTIMIZATION:    ${OPT}")
	ENDFOREACH()
ENDFOREACH()
MESSAGE(STATUS "make timing_<CIPHER>_<OPT> ................ Builds target for Time Measurement")
MESSAGE(STATUS "make testing_<CIPHER>_<OPT> ................Builds target for Testing")
MESSAGE(STATUS "------------------------------------------------------------------------------")
