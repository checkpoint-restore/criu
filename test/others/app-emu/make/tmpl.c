int foo(int a, int b)
{
#define A0(a, b)  ((a) + (b))
#define A1(a, b)  ((a) > (b)) ? A0((a) - (b), (b)) : A0((b) - (a), (a))
#define A2(a, b)  ((a) > (b)) ? A1((a) - (b), (b)) : A1((b) - (a), (a))
#define A3(a, b)  ((a) > (b)) ? A2((a) - (b), (b)) : A2((b) - (a), (a))
#define A4(a, b)  ((a) > (b)) ? A3((a) - (b), (b)) : A3((b) - (a), (a))
#define A5(a, b)  ((a) > (b)) ? A4((a) - (b), (b)) : A4((b) - (a), (a))
#define A6(a, b)  ((a) > (b)) ? A5((a) - (b), (b)) : A5((b) - (a), (a))
#define A7(a, b)  ((a) > (b)) ? A6((a) - (b), (b)) : A6((b) - (a), (a))
#define A8(a, b)  ((a) > (b)) ? A7((a) - (b), (b)) : A7((b) - (a), (a))
#define A9(a, b)  ((a) > (b)) ? A8((a) - (b), (b)) : A8((b) - (a), (a))
#define A10(a, b) ((a) > (b)) ? A9((a) - (b), (b)) : A9((b) - (a), (a))
#define A11(a, b) ((a) > (b)) ? A10((a) - (b), (b)) : A10((b) - (a), (a))
	return A10(a, b);
}
