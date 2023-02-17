#ifndef BPF_PARAM_H
#define BPF_PARAM_H

/* For parameter parsing in the evaluation script, please don't use block comments */

// Exp3 GAMMA
// GAMMA 0.0
//#define GAMMA(x) bpf_to_floating(0, 0, 1, &x, sizeof(floating)) // 0.0
//#define GAMMA_REV(x) bpf_to_floating(0, 0, 1, &x, sizeof(floating)) // 1/0.0 = infinity
//#define ONE_MINUS_GAMMA(x) bpf_to_floating(1, 0, 1, &x, sizeof(floating)) // 1 - 0.1 = 0.9

// GAMMA 0.01
//#define GAMMA(x) bpf_to_floating(0, 1, 2, &x, sizeof(floating)) // 0.01
//#define GAMMA_REV(x) bpf_to_floating(100, 0, 1, &x, sizeof(floating)) // 1/0.01 = 100
//#define ONE_MINUS_GAMMA(x) bpf_to_floating(0, 99, 2, &x, sizeof(floating)) // 1 - 0.01 = 0.99

// GAMMA 0.05
//#define GAMMA(x) bpf_to_floating(0, 5, 2, &x, sizeof(floating)) // 0.05
//#define GAMMA_REV(x) bpf_to_floating(20, 0, 1, &x, sizeof(floating)) // 1/0.05 = 20
//#define ONE_MINUS_GAMMA(x) bpf_to_floating(0, 95, 2, &x, sizeof(floating)) // 1 - 0.05 = 0.95

// GAMMA 0.1
//#define GAMMA(x) bpf_to_floating(0, 1, 1, &x, sizeof(floating)) // 0.1
//#define GAMMA_REV(x) bpf_to_floating(10, 0, 1, &x, sizeof(floating)) // 1/0.1 = 10
//#define ONE_MINUS_GAMMA(x) bpf_to_floating(0, 9, 1, &x, sizeof(floating)) // 1 - 0.1 = 0.9

// GAMMA 0.15
//#define GAMMA(x) bpf_to_floating(0, 15, 2, &x, sizeof(floating)) // 0.15
//#define GAMMA_REV(x) bpf_to_floating(6, 666666, 6, &x, sizeof(floating)) // 1/0.15 = 6.666666
//#define ONE_MINUS_GAMMA(x) bpf_to_floating(0, 85, 2, &x, sizeof(floating)) // 1 - 0.15 = 0.85

// GAMMA 0.2
#define GAMMA(x) bpf_to_floating(0, 2, 1, &x, sizeof(floating)) // 0.2
#define GAMMA_REV(x) bpf_to_floating(20, 0, 1, &x, sizeof(floating)) // 1/0.2 = 20
#define ONE_MINUS_GAMMA(x) bpf_to_floating(0, 8, 1, &x, sizeof(floating)) // 1 - 0.2 = 0.8

// GAMMA 0.5
//#define GAMMA(x) bpf_to_floating(0, 5, 1, &x, sizeof(floating)) // 0.5
//#define GAMMA_REV(x) bpf_to_floating(2, 0, 1, &x, sizeof(floating)) // 1/0.5 = 2
//#define ONE_MINUS_GAMMA(x) bpf_to_floating(0, 5, 1, &x, sizeof(floating)) // 1 - 0.5 = 0.5

// GAMMA 0.75
//#define GAMMA(x) bpf_to_floating(0, 75, 2, &x, sizeof(floating)) // 0.75
//#define GAMMA_REV(x) bpf_to_floating(1, 333333, 6, &x, sizeof(floating)) // 1/0.75 = 1.33...
//#define ONE_MINUS_GAMMA(x) bpf_to_floating(0, 25, 2, &x, sizeof(floating)) // 1 - 0.75 = 0.25

// GAMMA 0.9
//#define GAMMA(x) bpf_to_floating(0, 9, 1, &x, sizeof(floating)) // 0.9
//#define GAMMA_REV(x) bpf_to_floating(1, 111111, 6, &x, sizeof(floating)) // 1/0.9 = 1.11...
//#define ONE_MINUS_GAMMA(x) bpf_to_floating(0, 1, 1, &x, sizeof(floating)) // 1 - 0.9 = 0.1

#define USE_EXP3 1

#define MAX_REWARD_FACTOR 1
//#define MAX_REWARD_FACTOR 2
//#define MAX_REWARD_FACTOR 5
//#define MAX_REWARD_FACTOR 10
//#define MAX_REWARD_FACTOR 100

// 10 msec
//#define WAIT_BEFORE_INITIAL_MOVE 10000000
// 100 msec
//#define WAIT_BEFORE_INITIAL_MOVE 100000000
// 1 sec
#define WAIT_BEFORE_INITIAL_MOVE 1000000000

// Wait for this number of RTT before moving
#define WAIT_UNSTABLE_RTT 16

#define NBR_TOKENS 10000

#endif