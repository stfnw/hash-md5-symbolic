This repo implements the MD5 checksum/hash algorithm symbolically using the z3 SMT solver python API and its propositional logic / bitvector theories.
This allows formulating constraints on the inputs and outputs.

Of course this does not make it possible to break strong hashes because we quickly run into the exponentials!
But it nonetheless allows us to interactively explore the topic and find interesting pairs of inputs/outputs, like e.g. specific values at positions, fixed prefixes, or fixed suffixes.

TODO work in progress

# Examples

Here are some example input/output pairs I got while experimenting with this topic.
Note: All data input and hash output is hex encoded for easier printability.
The examples can be easily checked against the typical implementations available on Linux e.g. as follows:

```
printf 59db262ae923f6bed376763799172b93ca | xxd -r -p | md5sum
d7f3e5299129e1adfbc1e8a2edbcea00  -
```

| Input                              | Hash                             | Comment                               |
|------------------------------------|----------------------------------|---------------------------------------|
| 59db262ae923f6bed376763799172b93ca | d7f3e5299129e1adfbc1e8a2edbcea00 | hash ends in one null-byte            |
| 759beb48cd35dd4424f5afca2b333dec1a | 00e1b0ea98eaa5289136e4ad2bdcd78b | hash starts with one null-byte        |
| 803543ace73a1beda0f8192edc9c0307c9 | 0376f5df6c9bd61057dbd140b6a0f590 | hash starts and ends with 4 null bits |
