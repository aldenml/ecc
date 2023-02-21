#
# Copyright (c) 2021, Alden Torres
#
# Licensed under the terms of the MIT license.
# Copy of the license at https://opensource.org/licenses/MIT
#

include(FetchContent)

FetchContent_Declare(
    cmocka
    GIT_REPOSITORY https://git.cryptomilk.org/projects/cmocka.git
    GIT_TAG cmocka-1.1.6
    GIT_SHALLOW 1
)

set(WITH_STATIC_LIB ON CACHE BOOL "cmocka build static" FORCE)
set(WITH_CMOCKERY_SUPPORT OFF CACHE BOOL "cmocka with cmockery" FORCE)
set(WITH_EXAMPLES OFF CACHE BOOL "cmocka with examples" FORCE)
set(UNIT_TESTING OFF CACHE BOOL "cmocka with unit testing" FORCE)
set(PICKY_DEVELOPER OFF CACHE BOOL "cmocka with picky developer flags" FORCE)

FetchContent_MakeAvailable(cmocka)
