/* Extend caps01 with the legal ambient-before-securebits state. */
#define AMBIENT_SECUREBITS (SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED)
#include "caps01.c"
