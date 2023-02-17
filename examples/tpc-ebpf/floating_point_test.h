#ifndef FLOATING_POINT_TEST_H
#define FLOATING_POINT_TEST_H

#include "floating_point.h"
#include "utils.h"


/* Tests */

static void floating_test_to_floating() {
	floating float_1;
	__u32 number[2] = {0, 0};
    //to_floating(0, 1, 1, &float_1);
	//bpf_printk("[conv] 0.1 == mantisse %llu - exponent %d\n", float_1.mantissa, float_1.exponent - BIAS); // 0x%llx outside eBPF
	//floating_to_u32s(float_1, &integer_1, &decimal_1);
	//bpf_printk("[conv] 0.1 == %u.0*%u\n", integer_1, decimal_1);
    bpf_to_floating(0, 1, 1, &float_1, sizeof(floating));
	bpf_printk("[conv-kern] 0.1 == mantisse %llu - exponent %d\n", float_1.mantissa, float_1.exponent - BIAS); // 0x%llx outside eBPF
	bpf_floating_to_u32s(&float_1, sizeof(floating), (__u64 *) number, sizeof(number));
	bpf_printk("[conv-kern] 0.1 == %u.0*%u\n", number[0], number[1]);

	floating float_5;
    //to_floating(5, 0, 1, &float_5);
	//bpf_printk("[conv] 5 == mantisse %llu - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);
	//floating_to_u32s(float_5, &integer_5, &decimal_5);
	//bpf_printk("[conv] 5 == %u.0*%u\n", integer_5, decimal_5);
    bpf_to_floating(5, 0, 1, &float_5, sizeof(floating));
	bpf_printk("[conv-kern] 5 == mantisse %llu - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);
	bpf_floating_to_u32s(&float_5, sizeof(floating), (__u64 *) number, sizeof(number));
	bpf_printk("[conv-kern] 5 == %u.0*%u\n", number[0], number[1]);

	/*floating float_05;
    bpf_to_floating(0, 5, 1, &float_05, sizeof(floating));
	bpf_printk("[conv-kern] 0.5 == mantisse %llu - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);
	__u32 integer_05 = 0;
	__u32 decimal_05 = 0;
	floating_to_u32s(float_05, &integer_05, &decimal_05);
	bpf_printk("[conv] 0.5 == %u.0*%u\n", integer_05, decimal_05);

	floating float_55;
    bpf_to_floating(5, 5, 1, &float_55, sizeof(floating));
	bpf_printk("[conv-kern] 5.5 == mantisse %llu - exponent %d\n", float_55.mantissa, float_55.exponent - BIAS);
	__u32 integer_55 = 0;
	__u32 decimal_55 = 0;
	floating_to_u32s(float_55, &integer_55, &decimal_55);
	bpf_printk("[conv] 5.5 == %u.0*%u\n", integer_55, decimal_55);

	floating float_005;
    bpf_to_floating(0, 5, 2, &float_005, sizeof(floating));
	bpf_printk("[conv-kern] 0.05 == mantisse %llu - exponent %d\n", float_005.mantissa, float_005.exponent - BIAS);
	__u32 integer_005 = 0;
	__u32 decimal_005 = 0;
	floating_to_u32s(float_005, &integer_005, &decimal_005);
	bpf_printk("[conv] 0.05 == %u.0*%u\n", integer_005, decimal_005);

	floating float_10;
    bpf_to_floating(10, 0, 1, &float_10, sizeof(floating));
	bpf_printk("[conv-kern] 10.0 == mantisse %llu - exponent %d\n", float_10.mantissa, float_10.exponent - BIAS);
	__u32 integer_10 = 0;
	__u32 decimal_10 = 0;
	floating_to_u32s(float_10, &integer_10, &decimal_10);
	bpf_printk("[conv] 10.0 == %u.0*%u\n", integer_10, decimal_10);*/
}

static void floating_test_add() {
	__u32 add_dec [2] = {0, 0};
	floating terms [2];

	floating float_5;
    bpf_to_floating(5, 0, 1, &float_5, sizeof(floating));
	//bpf_printk("[add] 5 == mantisse 0x%llx - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);

	floating float_05;
    bpf_to_floating(0, 5, 1, &float_05, sizeof(floating));
	//bpf_printk("[add] 0.5 == mantisse 0x%llx - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);

	floating add;
	terms[0].mantissa = float_5.mantissa;
	terms[0].exponent = float_5.exponent;
	terms[1].mantissa = float_05.mantissa;
	terms[1].exponent = float_05.exponent;
	bpf_floating_add(terms, sizeof(floating) * 2, &add, sizeof(floating));
	bpf_floating_to_u32s(&add, sizeof(floating), (__u64 *) add_dec, sizeof(add_dec));
	bpf_printk("[add] 5 + 0.5 == 5.5 == %u.%u\n", add_dec[0], add_dec[1]);

	terms[1].mantissa = float_5.mantissa;
	terms[1].exponent = float_5.exponent;
	terms[0].mantissa = float_05.mantissa;
	terms[0].exponent = float_05.exponent;
	bpf_floating_add(terms, sizeof(floating) * 2, &add, sizeof(floating));
	bpf_floating_to_u32s(&add, sizeof(floating), (__u64 *) add_dec, sizeof(add_dec));
	bpf_printk("[add] 0.5 + 5 == 5.5 == %u.%u\n", add_dec[0], add_dec[1]);
}

static __always_inline void floating_test_multiply() {
	__u32 mult_dec [2] = {0, 0};
	floating factors [2];

	floating float_5;
    bpf_to_floating(5, 0, 1, &float_5, sizeof(floating));
	//bpf_printk("[mult] 5 == mantisse 0x%llx - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);

	floating float_05;
    bpf_to_floating(0, 5, 1, &float_05, sizeof(floating));
	//bpf_printk("[mult] 0.5 == mantisse 0x%llx - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);

	floating mult;
	factors[0].mantissa = float_5.mantissa;
	factors[0].exponent = float_5.exponent;
	factors[1].mantissa = float_05.mantissa;
	factors[1].exponent = float_05.exponent;
    bpf_floating_multiply(factors, sizeof(floating) * 2, &mult, sizeof(floating));
	bpf_floating_to_u32s(&mult, sizeof(floating), (__u64 *) mult_dec, sizeof(mult_dec));
	bpf_printk("[mult] 5 * 0.5 == 2.5 == %u.%u\n", mult_dec[0], mult_dec[1]);
}

static void floating_test_divide() {
	__u32 div_dec [2] = {0, 0};
	floating operands [2];
	floating float_5;
    bpf_to_floating(5, 0, 1, &float_5, sizeof(floating));
	//bpf_printk("[div] 5 == mantisse 0x%llx - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);

	floating float_05;
    bpf_to_floating(0, 5, 1, &float_05, sizeof(floating));
	//bpf_printk("[div] 0.5 == mantisse 0x%llx - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);

	floating div;
	operands[0].mantissa = float_5.mantissa;
	operands[0].exponent = float_5.exponent;
	operands[1].mantissa = float_05.mantissa;
	operands[1].exponent = float_05.exponent;
	bpf_floating_divide(operands, sizeof(floating) * 2, &div, sizeof(floating));
	bpf_floating_to_u32s(&div, sizeof(floating), (__u64 *) div_dec, sizeof(div_dec));
	bpf_printk("[div] 0.5 / 5 == 0.1 == %u.%u\n", div_dec[0], div_dec[1]);

	operands[1].mantissa = float_5.mantissa;
	operands[1].exponent = float_5.exponent;
	operands[0].mantissa = float_05.mantissa;
	operands[0].exponent = float_05.exponent;
	bpf_floating_divide(operands, sizeof(floating) * 2, &div, sizeof(floating));
	bpf_floating_to_u32s(&div, sizeof(floating), (__u64 *) div_dec, sizeof(div_dec));
	bpf_printk("[div] 5 / 0.5 == 10 == %u.%u\n", div_dec[0], div_dec[1]);
}

static void floating_test_exp() {
	__u32 exp_dec [2] = {0, 0};
	floating result;

	floating float_5;
    bpf_to_floating(5, 0, 1, &float_5, sizeof(floating));
	//bpf_printk("[exp] 5 == mantisse 0x%llx - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);

	floating float_05;
    bpf_to_floating(0, 5, 1, &float_05, sizeof(floating));
	//bpf_printk("[exp] 0.5 == mantisse 0x%llx - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);

	bpf_floating_e_power_a(&float_5, sizeof(floating), &result, sizeof(floating));
	bpf_floating_to_u32s(&result, sizeof(floating), (__u64 *) exp_dec, sizeof(exp_dec));
	bpf_printk("[exp] e^5 == 148.413159102 == %u.%u\n", exp_dec[0], exp_dec[1]);

	bpf_floating_e_power_a(&float_05, sizeof(floating), &result, sizeof(floating));
	bpf_floating_to_u32s(&result, sizeof(floating), (__u64 *) exp_dec, sizeof(exp_dec));
	bpf_printk("[exp] e^0.5 == 1.648721270 == %u.%u\n", exp_dec[0], exp_dec[1]);
}

static int floating_test_all() {
    bpf_printk("[main] Before to floating\n");
	floating_test_to_floating();
    bpf_printk("[main] Before divide\n");
	floating_test_divide();
    bpf_printk("[main] Before multiply\n");
	floating_test_multiply();
    bpf_printk("[main] Before add\n");
	floating_test_add();
    bpf_printk("[main] Before exp\n");
	floating_test_exp();
    bpf_printk("[main] All tests performed\n");
	return 0;
}

#endif