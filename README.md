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

Some hashes were the i-th byte is zero:

| Input                              | Hash                                 |
|------------------------------------|--------------------------------------|
| `e6cb4a7a8637bf2306ea5e5fb0134ff5ea` | `0041d7ab5a1cbbc9a42856e6d186ff6c` |
| `c5abdd26381dbe82bf3b0ed30fb452c5b3` | `9400e1ff3b87654db09d2574794800b2` |
| `4baf8ddfa7c45a6db264921b57698169fe` | `32be00bea4f660a6ff3a2e07cc326f8a` |
| `aa7b839e3c18153053ed66159bb6857d73` | `3323f200a234991a00a1c15550bf6005` |
| `0d92f2b909e61519a676406da772ccf97a` | `e505170300fe041df8d93aa5b310e85a` |
| `f8b11cd7863ff53471b9fe3cff8da65937` | `c358bcb2f00078baca82533f5af51de8` |
| `2820ab9ba0e2aa82cda384015dff5a36fb` | `c46e470f849100d147aeb40c77840434` |
| `15d96fc251dfdcfa9571e613d591ef8958` | `6ddf764eec76e600380910e9edb1247f` |
| `79b3a79d9822ff6bb29404ad217e901d03` | `9cd7695f4842a13a00ec1a0512330b2b` |
| `2c2d85ccedd59d703064ed5b0ad65eaf08` | `58fef5397521949f710055e4c2673049` |
| `9ed8e7f9a84827b50e4990cea221dd1b6d` | `6aa7c52977a2d6bb3ee000b269aca80d` |
| `188be9e3d617fa66fcd3faab4f21a171d9` | `6cba9b5b43c1ae9d8c6f7400c84b4214` |
| `521c3a9849bd24123bf9917dc98e5937d8` | `3256393fe813cef08c8233df0079eb7e` |
| `8b3f36073463da2dacbb05aae0b185824c` | `a0e9696c49d24e74d606998c63007051` |
| `128877b68e3ec1b3aa44e92f3abb41107d` | `29c9d7d6b157a93721987836b56200ae` |
| `a24746e7b1efc1c95ab9d2f0e8891cc4ff` | `bc734430bb52c5d49b85e1a865a98600` |

Some hashes were the i-th nibble in the input and the hash are the same:

```
       |
Input: adc3822adc60266c6da6fe411b17238b03
Hash:  a7d364da10e5c920d31f31fda3b483ec

        |
Input: 917bb8a51b6422af6f52859fb303741603
Hash:  a1d4ab369fa7e69e39a5a8c6b21d7ab8

         |
Input: 1798ae2940b0cf016cefd50521b11914bc
Hash:  d89227dbb5f303a438ce4788d93d1fbb

          |
Input: d0843c0ee5899e84c96e0e3d57e920b5fe
Hash:  21f4004a18b52e0cb4764125ef0db96e

           |
Input: ea06379f9cd7297bf366185cbc7fdefdaf
Hash:  f2733b7e8c2a224ebc621e60574b2c3b

            |
Input: 97b975f31caf8d09459ac1e38146f29af1
Hash:  5a8f554d1349afbf45a6c99bd08c07a0

             |
Input: 881e0b695978c6397eda545a896080bff7
Hash:  bd695e69b94a8bf890a699eba0c3edde

              |
Input: 9a8cf726ce1b74ed9ec77e324fced630cc
Hash:  b4b56e0684c5a25586f824ab1a95e316

               |
Input: 693a0741e01db7b379abb31643aeca54a3
Hash:  93cc95f2ebad38d3da453272788d31e6

                |
Input: 3f9c8c6c2d9da36449fe299ca8ed6723ff
Hash:  bab172213dc6f1f774bc5ab90802a5e0

                 |
Input: d053e27fb9f9144810b35beec6a7a49fcd
Hash:  7fe44498c6f4443c477ae8580604e5bf

                  |
Input: 24026e346c6247d0eb20319ac17b84f8da
Hash:  fd230658cbf22cd5af3a9e6b28f4ee9b

                   |
Input: 8e2b58c3a519b45f9ef77141f70121620a
Hash:  bfa7242d8a63b2fb2b6de44e8a5ce93c

                    |
Input: 918008b25574c5aee9c76658fdaf694ef5
Hash:  b016bc9930c2d5959a72e3ead6f62d52

                     |
Input: 915d6f4bb8ab545a609da8dfdcb69e3f33
Hash:  828f898347d33c50400989c755a6d8ff

                      |
Input: a3c564323de1a538a2c7787dbcdfb602a7
Hash:  16eb92bc4b6e4bd845987be03c198e2a

                       |
Input: 9952a252b4b9e1df5d639b3c55e5e4d721
Hash:  40b44bd91dee9784530b9c9a648c0274

                        |
Input: 90bcc10c54035b71b3ac373bc4d8bab5ff
Hash:  0874c9a97591fc4983afddaa5366396b

                         |
Input: 867ff5e8f936584d0383789dd98b633da9
Hash:  dd7f2df10409aedc588378003779d144

                          |
Input: 91c0b288853a1f447ba09b931b4213d3d4
Hash:  f7088073219ea39a2af0faa4a2679029

                           |
Input: 62c9207b4e01563f65dd6b8b121bdb33f3
Hash:  e55bc4e0df0886e4cf9663674444c989

                            |
Input: 9b8c0a2d5763ac112655f303d10b85116a
Hash:  131133473aa85253ad5d13aa58094a56

                             |
Input: 5ffac6f08ff38170252d83f8cb8bfa5fff
Hash:  89581d00c97442d9559e91ff2d2f437d

                              |
Input: 9af0d57c7e338cfcb7949bc5b168ad2aba
Hash:  dbd63e6176c25920560d0a85a937bb04

                               |
Input: 10a69d9126593f79b89ca4a84694fd47a5
Hash:  b1c16addc5c18339255b50e9486f3f1a

                                |
Input: 73676f94b70d732b8fd19e7598527715cb
Hash:  8b0139171ac367043fbf444c581d6093

                                 |
Input: 880bd6f8aa919584d52a0c0729604e22e3
Hash:  f2b9c4930b3a99de130c6ce74d6dc25f

                                  |
Input: dd0fe25f303c760b4619a80cba0b583e08
Hash:  040c9c23fd5279ca0729e0bdd83b21a1

                                   |
Input: e68fa487ebb352156773cf02d35ba11223
Hash:  f20d2ee4927be8130130e0738e5fa46a

                                    |
Input: 1a5be0ca08be7810a7386455ae89b71bbe
Hash:  c1198deec455d115069488b91abf1744

                                     |
Input: 876b6811d0d524a4d8c24f5722fd1d77ea
Hash:  216233bde02c00433d6254726e82e277

                                      |
Input: 4fcbd20a486451d030dfa12e1043fda626
Hash:  cd547ca8c06262320dd5873c2a4dcca6
```
