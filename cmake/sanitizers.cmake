option(SANITIZERS "Enable sanitizers" OFF)
if(SANITIZERS)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g -fno-omit-frame-pointer -fsanitize=address")
endif()