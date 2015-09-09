#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>

#include "zdtmtst.h"

/*
 * This test is specific to PowerPC
 */
#ifndef _ARCH_PPC64
int main(int argc, char *argv[])
{
	test_init(argc, argv);
	skip("Unsupported arch");
	return 0;
}

#else

#include <sys/auxv.h>
#include <asm/cputable.h>

/*
 * This test verifies that data stored in the VSX regsiters are still there
 * once the restart is done.
 *
 * The test is filling the registers with dedicated values and then check
 * their content.
 */

const char *test_doc	= "Test if data in vector registers do survive the c/r";
const char *test_author	= "Laurent Dufour <ldufour@linux.vnet.ibm.com>";

int is_test_doable(void)
{
	unsigned long val;

	val = getauxval(AT_HWCAP);
#define CHECK_FEATURE(f) do {						\
		if (!(val & f)) {					\
			test_msg("CPU feature " #f " is missing\n");	\
			return 0;					\
		}							\
	} while(0)

	CHECK_FEATURE(PPC_FEATURE_64);
	CHECK_FEATURE(PPC_FEATURE_HAS_ALTIVEC);
	CHECK_FEATURE(PPC_FEATURE_HAS_VSX);
	return 1;
}

void fill_vsx(uint64_t *pt)
{
	asm volatile(
	    "lis	3, 0		\n"

	    "lxvd2x	0, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	1, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	2, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	3, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	4, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	5, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	6, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	7, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	8, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	9, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */

	    "lxvd2x	10, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	11, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	12, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	13, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	14, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	15, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	16, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	17, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	18, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	19, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */

	    "lxvd2x	20, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	21, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	22, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	23, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	24, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	25, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	26, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	27, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	28, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	29, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */

	    "lxvd2x	30, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	31, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	32, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	33, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	34, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	35, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	36, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	37, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	38, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	39, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */

	    "lxvd2x	40, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	41, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	42, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	43, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	44, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	45, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	46, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	47, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	48, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	49, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */

	    "lxvd2x	50, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	51, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	52, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	53, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	54, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	55, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	56, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	57, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	58, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	59, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */

	    "lxvd2x	60, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	61, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	62, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "lxvd2x	63, 3, %0	\n"
	    : /* no output */
	    : "r" (pt)
	    : "3");
}

void read_vsx(uint64_t *pt)
{
	asm volatile(
	    "lis	3, 0		\n"

	    "stxvd2x	0, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	1, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	2, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	3, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	4, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	5, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	6, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	7, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	8, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	9, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */

	    "stxvd2x	10, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	11, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	12, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	13, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	14, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	15, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	16, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	17, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	18, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	19, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */

	    "stxvd2x	20, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	21, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	22, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	23, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	24, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	25, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	26, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	27, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	28, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	29, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */

	    "stxvd2x	30, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	31, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	32, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	33, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	34, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	35, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	36, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	37, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	38, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	39, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */

	    "stxvd2x	40, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	41, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	42, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	43, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	44, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	45, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	46, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	47, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	48, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	49, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */

	    "stxvd2x	50, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	51, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	52, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	53, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	54, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	55, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	56, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	57, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	58, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	59, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */

	    "stxvd2x	60, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	61, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	62, 3, %0	\n"
	    "addi	3, 3, 16	\n" /* move to the next qword */
	    "stxvd2x	63, 3, %0	\n"

	    : /* no output */
	    : "r" (pt)
	    : "3");
}

int main(int argc, char *argv[])
{
	/* A random buffer of 1024 bytes (64 * 128bit registers to fill) */
	static const char ibuffer[128/8*64]=
		"sahwoleiGun9loosliz0Aech9aiph5eiIengei7Ogh8zu7ye"
		"Aeshie6vai0thaehool1ooK6ayaj3Neitahn8yeeh5ahfuiT"
		"uCeir1bife4ieceema8choo2Wengaec1seDaidohteipa4ai"
		"aequee7AiriejaeJar1giak8Gei2uathloh5uemaeG6EiSoo"
		"PhaenaethoPhej8nEecheegeihosho8Zohroo8ea6Juuheif"
		"nu2Hahvai1tuf0Zeeeveephu2EitaexiVaekieboac7Nushu"
		"aeTh6Quoo3iozeisaudaGheed0aPah2Schoog0eiChaeN5su"
		"xoo1phoic1mahXohSai1thoogo0oesooeaxai7eBahHahMue"
		"quiloh2ooPahpiujeithae0Dau0shuwicobinaaYooj0ajiw"
		"iiheeS4awoh3haevlaiGe8phaev3eiluaChaF6ieng4aith4"
		"aif3TooYo1aigoomZiuhai8eesoo4maiLahr3PoM8Eir5ooz"
		"Iequ9ahre4Op4bahaiso6ohnah8Shokimooch1Oafahf5aih"
		"xohphee1pi5Iecaiaigh7Eisah2uew5acie7wi6Zo0Eelah9"
		"woi8QueerohfeiThaBoh5jaic3peiPohAhng0bu5shoop7ca"
		"Qui5kodaika8quioahmohreeVe8loquaeeLi5ze3oceiHa0l"
		"roh8Ooxae7uish9ioog7ieS3aibeo2thOosiuvaiS5lohp4U"
		"emieG0eit6Bien8EzaiwiTh3geighaexshee8eHiec1TooH2"
		"Eeceacai0inaejieboo8NeishieweiraHooj9apeecooy0th"
		"daThei6aexeisahdsei3keik0diPheejchais6ezo0iep5Ae"
		"Wiqu6aepeing4ba8diek3aev9waYooveAebai9eef6Iex6vo"
		"Quee9MeitahMighoHuo3seveeMoh3ohtoxaib6ootaiF5EeT"
		"Ohb9eijoonoh6ich";
	char obuffer[128/8*64];
	int do_test;

	test_init(argc, argv);

	do_test = is_test_doable();

	if (do_test) {
		memset(obuffer, 0xFF, sizeof(obuffer));
		fill_vsx((uint64_t *)ibuffer);
	}

	test_daemon();
	test_waitsig();

	if (do_test) {
		read_vsx((uint64_t *)obuffer);

		if (!memcmp(ibuffer, obuffer, sizeof(ibuffer)))
			pass();
		else {
			test_msg("Data mismatch\n");
			fail();
		}
	}
	else {
		test_msg("The CPU is missing some features.\n");
		fail();
	}

	return 0;
}

#endif /* _ARCH_PPC64 */
