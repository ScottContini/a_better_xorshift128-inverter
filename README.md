# a_better_xorshift128-inverter
xorshift128+ is behind JavaScript v8 Math.random() function.  Did you know that given 2 outputs of xorshift128+, you can determine all past and future states?  This repo shows how to do it.

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

