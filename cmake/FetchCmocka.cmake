include(FetchContent)

FetchContent_Declare(
    cmocka
    GIT_REPOSITORY https://git.cryptomilk.org/projects/cmocka.git
    GIT_TAG cmocka-1.1.5
    GIT_SHALLOW 1
)

set(WITH_STATIC_LIB ON CACHE BOOL "cmocka build static" FORCE)

FetchContent_MakeAvailable(cmocka)
