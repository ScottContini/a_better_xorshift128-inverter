# a_better_xorshift128_inverter
xorshift128+ is behind JavaScript v8 Math.random() function.
In most cases you only need 2 outputs to predict all past and future outputs with certainty,
but in some cases you need 3 outputs.
This repo demonstrates the inversion with 2 or 3 outputs.
I have a complete write-up of the algorithm for inverting it
in [my blog](https://littlemaninmyhead.wordpress.com/2025/08/31/inverting-the-xorshift128-random-number-generator/).

This repo contains 2 programs as follows:

- xorshift128.c : this program will take command line input for the seed, and provide observed outputs
to be fed into the other program.

- a_better_inverter.c : this program will take command line input of the consecutive observed outputs
from the first program, and retrieve all seeds that match the first 2 outputs.  If you
provide 3 outputs in the command line, it is very likely that there is only one seed so it
will derive the exact seed that will match all outputs.


## xorshift128.c compilation:

```bash
gcc xorshift128.c
```

## xorshift128.c usage

```bash
./a.out seed0 seed1
```

## a_better_inverter.c compilation:


```bash
gcc -O3 a_better_inverter.c -o inverter.out
```

## a_better_inverter.c Usage

```bash
./inverter.out x0 x1 
```

or

```bash
./inverter.out x0 x1 x2
```

## Example
For example
```bash
./a.out 0xbabef00d12345678 0x12345678abcdef
```

This will output

```bash
Taking seeds from command line
Initial seed was 0xbabef00d12345678 0x12345678abcdef
The observed outputs are:
	0xbc37b4c21fad6702
	0x533174ceb893a293
	0xb609a47e0f4f2897
	0xd77c8e560bae17f8
	0x647c977ce121cb0c
	0xba038712153e9631
	0x1317b7415767c56b
	0xe8473ac18b0ebb05
Use at least 2 (prefer 3) consecutive outputs in other program to find initial seed
```

We can then do

```bash
./inverter.out 0xbc37b4c21fad6702 0x533174ceb893a293 0xb609a47e0f4f2897
```

or 

```bash
./inverter.out 0xbc37b4c21fad6702 0x533174ceb893a293
```


