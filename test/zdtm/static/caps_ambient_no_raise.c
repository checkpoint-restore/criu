/* The no-raise bit also forbids restoration when it is not locked. */
#define AMBIENT_SECUREBITS SECBIT_NO_CAP_AMBIENT_RAISE
#include "caps01.c"
