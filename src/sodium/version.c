

int
sodium_library_minimal(void)
{
#ifdef SODIUM_LIBRARY_MINIMAL
    return 1;
#else
    return 0;
#endif
}
