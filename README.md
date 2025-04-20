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

| Input                                | Hash                               | Comment                               |
|--------------------------------------|------------------------------------|---------------------------------------|
| `59db262ae923f6bed376763799172b93ca` | `d7f3e5299129e1adfbc1e8a2edbcea00` | hash ends in one null-byte            |
| `759beb48cd35dd4424f5afca2b333dec1a` | `00e1b0ea98eaa5289136e4ad2bdcd78b` | hash starts with one null-byte        |
| `803543ace73a1beda0f8192edc9c0307c9` | `0376f5df6c9bd61057dbd140b6a0f590` | hash starts and ends with 4 null bits |

Some hashes were the i-th nibble is zero:

| Input                                | Hash                                |
|--------------------------------------|-------------------------------------|
| `8c0763affa0b10984a4471c665163bd716` | `.09b9dfa245702e3c442ba40daac9454b` |
| `5d5ba70de3c4b86d7f74cf79da3ef71b51` | `2.09cbd8bf021fa377c21d1859d69a24e` |
| `22da892c6c24f56f471d18283728467618` | `73.0c30a76903c12e1f1f2de16eb06912` |
| `8fe41827537859e4e1e659d062dc98d253` | `0d7.0413800bb520ac501e3b9ea2e5590` |
| `f347cf81e72d8a603fa22d8f3a37ab5d7d` | `f6f1.0f99c201b9e0f43a7d688227a7c9` |
| `a26df9189ea38ce0c2de6f733954432300` | `dc204.0229d63265f918e51fa846c001f` |
| `12e84691c10e2c2c89e53890174abe9fe1` | `cf250e.0342ea578f9c0234810818f9e3` |
| `d93404213752557f30deb4655868cceaf5` | `91c3eab.0866962cde19d367ee3286c30` |
| `27cb0f679ed535a0841bd462dac4a3b2da` | `3c3d0761.059148bf00242d8f1238bb83` |
| `72c388e2a7716e553a3e2b47cd45a21f01` | `22b1747f9.0ecac068f9202965453a94d` |
| `a83b76e0466bb2c87c930661fd31235dc5` | `91171e2f7e.042a4c58e426df8529ef52` |
| `46a0dc48a67fb6d50596305beb5ab693bb` | `7ddf00b16c6.0dce7d1b575755dc83100` |
| `6795b053f6923599bac18c320d1fabc0dc` | `d8c5bdae63cb.01984abb282480477f56` |
| `6711062deecfa72e3b93a7fa74b815eedf` | `8e80450d92ada.0623ecc15541af1ca58` |
| `8fd72df9728178e7d9e0a0e68fd6f0da47` | `1ae6f36bced289.0906ce9d5614606ec9` |
| `9d238c8571ac3cc328c51696b2fc853868` | `94e46add160592c.0692ce298e2147c17` |
| `c9c31ab779a7e46c596a088d1cd59a0e06` | `c0e444def2a269d5.0fb640ef83cf5fa2` |
| `873cef9f011c756892562f9c3c369da80b` | `31836b777a3ead8ea.08bb37e40bf274a` |
| `b56998796dabbd3972a5168b5841c4878b` | `32c75cd75b0d02e87b.0eb07cf55263a7` |
| `a6dace9e1bff21a464dffdddb778202a8c` | `dae15585386de373cfd.078f9a91bc34c` |
| `f37e46173ec66f41a74c4abe496749428e` | `ab8513f12f4533eff7be.09073437f904` |
| `28ac1921ae808657f6009255863dc6c6f6` | `45e2ea3f9a730d69cb02b.0104308a614` |
| `08c7c91fdedad25be36061b7b68f405601` | `72fc43f72198fae79f0c24.0056be311f` |
| `ae9bca39461b4fe920588c4481c9c930ab` | `5b0b003a0978a60c01195db.0b198f213` |
| `9309ff69003af8e283dc9419958b259a90` | `c8b7ba030ae43dfaa3504d11.0353caca` |
| `f0ec7028f8f67b540b6e9c5c87808013ab` | `f154abb42ea006404dbe5707b.0c1e270` |
| `d1538223047b7e6f2ba181e3f19f124305` | `c0901086a181be4304b5fa7747.0ada97` |
| `c7b026643b80fd5f0fcd36337282402a53` | `c9a42179116c81f11ff7ebabe36.0795b` |
| `875f01b17b76864172fbd4656c7db70009` | `f19dec029c3bb5e330eacbb1ba69.0744` |
| `8a42216503c09cdef7c8d2b7e6afbfc902` | `dd696f37baea336bea3a2784b2b54.0d4` |
| `b26738d8b290586204740cd5a2d27003df` | `37caff1f7cd897c7a445b31a147f17.0e` |
| `ece2f62823dc94aec24d497d186f87e89a` | `cc1666af0cce0d0379b332d66fe4b9b.0` |
