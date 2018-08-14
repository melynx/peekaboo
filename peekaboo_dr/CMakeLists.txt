find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

add_library(peekaboo_dr SHARED "peekaboo_dr.c")
configure_DynamoRIO_client(peekaboo_dr)
use_DynamoRIO_extension(peekaboo_dr drmgr)
use_DynamoRIO_extension(peekaboo_dr drreg)
