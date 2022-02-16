Rubidium is a fork of the Sodium cryptographic library.

The main goals of rubidium is to strip as much complexity as possible,
convert everything to use CMake only (and thus support things like
CMake export sets) and add C++ features like namespaces.

While Sodium has proven itself to be a capable library, the complexity
and inconsistency of the implementation makes it difficult for others
to read and understand the code. Autotools is a nightmare and needs to
be eradicated. The conversion to CMake will ensure that the build
system is readable.

It's also been noticed that Sodium seems to take advantage of undefined 
behavior, assuming such code will compile correctly on "all supported
platforms". Rubidium will not take such a cavalier approach, and all
behavior should be well-defined by the C++ standard.
