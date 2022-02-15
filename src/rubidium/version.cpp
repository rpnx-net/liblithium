

int
rubidium_library_minimal(void)
{
#ifdef RUBIDIUM_LIBRARY_MINIMAL
    return 1;
#else
    return 0;
#endif
}
