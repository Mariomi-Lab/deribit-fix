
#set(CMAKE_PREFIX_PATH "/Volumes/Ventura - Data/projects/crypto")

#FIND_PATH(QUICKFIX_PATH quickfix)

set(QUICKFIX_PATH "/usr/local")

if(WIN32)
	set(quickfix_DEPENDENCIES wsock32 ws2_32)
	set(quickfix_LIBRARY ${quickfix_DEPENDENCIES} ${QUICKFIX_PATH}/quickfix/lib/debug/quickfix.lib)
	set(quickfix_INCLUDE_DIRS ${QUICKFIX_PATH}/quickfix/include)
else()
	set(quickfix_DEPENDENCIES pthread)
	set(quickfix_LIBRARY ${quickfix_DEPENDENCIES} ${QUICKFIX_PATH}/lib/libquickfix.dylib)
	set(quickfix_INCLUDE_DIRS ${QUICKFIX_PATH}/include)
endif()
 
if(CMAKE_BUILD_TYPE MATCHES Release)
	set(quickfix_LIBRARY ${quickfix_DEPENDENCIES} ${QUICKFIX_PATH}/quickfix/lib/quickfix.lib)
endif()