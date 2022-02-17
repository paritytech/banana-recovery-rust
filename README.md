
# Crate `banana_recovery`

**Warning!** This is development version, please do not use for anything important (see warning below).

## Overview

This is a lib crate for recovering secrets from a set of shares generated using [banana split protocol](https://github.com/paritytech/banana_split).  

The crate is mainly intended to be used as a part of [Signer](https://github.com/paritytech/parity-signer). For the time being, the crate is intended only to *recover* secrets, with no secret generation part present.  

The code is following the published javascript code for banana split recovery from `https://github.com/paritytech/banana_split`. The combining of shares into encrypted secret is re-written in rust and generally follows the published javascript code for Shamir's Secret Sharing from `https://www.npmjs.com/package/secrets.js-grempe`.  

## Comments  

In principle, the Shamir's Secret Sharing from `https://www.npmjs.com/package/secrets.js-grempe` supports `bits` values (i.e. the value n defining the size of Galios field GF(2^n) and the possible number of shares) in range `3..20`. The bits are set up during the `init` (here: `https://github.com/grempe/secrets.js/blob/master/secrets.js#L472`), defaulting to `8`. The V1 in banana split uses the default value. This crate supports range `3..20`, could be useful in case other banana split versions appear.  

When pre-calculating logarithms and exponents values within GF(2^n), all exponents are generated in same order as they are written in the collecting vector, so naturally all of them are existing. Due to the properties of GF, all logarithms are also get filled in eventually, except `log[0]` that remains undetermined.  
During Lagrange polynomial calculation, certain `log[i]` values are summed up, and the resulting `product` is used to calculate the exponent `exp[product]` to be xored with final collected value. Summing logs and calculating exponent from sum is a common convenient way of multiplying values.  
When `log[0]` get addressed, it means that 0 participates in multiplication, the total multiplication result is 0, xoring will not change anything. So the whole cycle element gets skipped in this case.  

### XSalsa20Poly1305  

This crate task is to recover whatever was in qr code set. The crate `xsalsa20poly1305` has the NaCl algorithm that does the job, even though it may be not the ideal one. In case the encryption protocol changes in later banana split versions, this crate will get accordingly updated.  

**Warning!**  
Currently the `xsalsa20poly1305` crate depends on `zeroize` version conflicting with the one used in Signer. This is temporarily fixed by forking and updating dependencies in xsalsa, but to be done properly awaits on xsalsa upstream, hopefully happening at some point.

### Zeroize  

Supposedly the real shares get scanned from paper qr codes, with real passphrase written on same paper nearby. If someone has the paper share, they of course can read the qr code, and know the passphrase, nonce, title, and single share content. If they have enough shares, they get the secret, elsewise - not, by design of SSS.  
Now, is someone takes the Signer and reads its raw memory, after the Signer was used to recover banana shares, they may get access to residuals of the Share and ShareSet structs. Without passphrase the breaking is difficult (xsalsa). Things change if both Signer and one paper share are taken, i.e. the passphrase and the set are potentially stolen. For now no zeroize is done on encrypted secret or secret shards. If need be, could be easily added.  
The passphrase does not get processed or cloned in this crate, only send into `scrypt` (todo: check upstream). The decoded secret from `xsalsa20poly1305` (todo: check upstream) is received as Vec<u8>, and converted into String without processig or cloning. If conversion is successful, String goes into output. If there is error, the error contains the received secret, and should be zeroized (after all, secret got decoded).  
