CX contact tracing
==================

``libcx`` provides a Python abstraction for the data formats and
operations defined by the [CX contact tracing
architecture](https://cx.ipxe.org).

```python
import libcx

# Construct a Preseed Value and Preseed Key Pair
preseed = libcx.Preseed.value(libcx.CX_GEN_AES_128_CTR_2048)
key = libcx.Preseed.key()

# Construct a Seed Calculator
seedcalc = libcx.SeedCalculator(libcx.CX_GEN_AES_128_CTR_2048, preseed, key)

# Construct a Generator
gen = seedcalc.generator

# Construct a list of Contact Identifiers
ids = list(gen)
```
