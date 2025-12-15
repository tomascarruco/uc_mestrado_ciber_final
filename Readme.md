# Artigo Ciber Segurança

## Abstract

The proliferation of IoT devices across critical infra
structure, healthcare, and industrial applications has intensified
security concerns, as many resource constrained devices imple
ment inadequate cryptographic protections. While established
cryptosystems provide robust security, their computational and
energy demands often exceed the capabilities of low power
microcontrollers. Hardware cryptographic accelerators inte
grated into modern System on Chip (SoC) platforms partially
address these constraints, but accelerator support varies signif
icantly across manufacturers—creating substantial performance
heterogeneity that complicates algorithm selection for resource
constrained deployments. This paper presents a comprehensive
performance characterization of symmetric and asymmetric
cryptosystems across heterogeneous SoC platforms from multi
ple manufacturers, profiling behavior under three operational
regimes: nominal conditions, peak computational load, and
adverse power supply scenarios. The study measures encryption/
decryption latency, power consumption, memory utilization,
CPU overhead, and thermal behavior across variable key sizes,
leveraging native hardware accelerators where available. Criti
cally, controlled power supply perturbations are introduced to
simulate real world voltage instability and assess cryptographic
resilience under resource degradation. The resulting empirical
dataset enables the development of decision support tools that
can guide developers in selecting cryptographic configurations
based on hardware capabilities, power constraints, and appli
cation requirements, providing a foundation for intelligent
algorithm selection in power constrained and fault prone IoT
deployments.

The paper can be found [here](./ArtigoCiber.pdf).

## Project Structure

```bash
.
├── ArtigoCiber.pdf
├── boards
│   ├── esp32s3
│   ├── nano_33_iot
│   │   ├── compile_commands.json
│   │   ├── include
│   │   │   ├── README
│   │   │   └── secrets.h
│   │   ├── lib
│   │   │   └── README
│   │   ├── Makefile
│   │   ├── platformio.ini
│   │   ├── sketch.yaml
│   │   ├── src
│   │   │   └── main.cpp
│   │   └── test
│   │       └── README
│   └── rp2350
├── Readme.md
└── server
    ├── go.mod
    ├── go.sum
    └── main.go
```
> 10 directories, 14 files

---

## Knowledge Base

### Crypto-Systems and Encription Algorithms

#### Algorithm List

1. AES 
2. DES 
3. 3DES 
4. ChaCha20 
5. RC4 
6. Salsa20
7. RSA 
8. ECDH 
9. DSA 
10. AES-GCM 
11. ChaCha20-Poly1305

#### Embedded Implementation details

To avoid implementation erros, and acctualy enable us to write, validate and
experiment with the selected algorithms and boards, we've chosen to utilize
the Crypto++ library, which can be found [here](https://cryptopp.com/).

This library implements all of the algorithms proposed in the paper's proposal.
Taking the embedded-focus nature of this papaer, we've decided to use the
following platformio package - theclocktwister/Crypto++

