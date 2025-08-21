# a_better_xorshift128-inverter
xorshift128+ is behind JavaScript v8 Math.random() function.
In most cases you only need 2 outputs to determine all past and future states with certainty,
but in some cases you need 3 outputs.
This repo demonstrates the inversion with 3 outputs, but it also has a function
`search_from_2_outputs( )` that shows that it works most of the time with only 2 outputs.


## Compilation:

```bash
gcc -O3 a_better_inverter.c
```

## Usage

```bash
./a.out seed0 seed1
```

For example
```bash
./a.out 0xbabef00d12345678 0x12345678abcdef
```

More coming soon, stay tuned.

