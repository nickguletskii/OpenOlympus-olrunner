set(EXECUTABLE_OUTPUT_PATH ${OUTPUT_DIR})
add_executable (olrunner runner.cpp)
target_link_libraries (olrunner sandbox) 
INSTALL(TARGETS olrunner
  RUNTIME DESTINATION bin
)