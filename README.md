# trabant
A C library meant to be used with [Emscripten](https://github.com/kripken/emscripten) to provide some needed cryptographic primitives in Javascript, or, in our case, [Clojurescript](https://github.com/clojure/clojurescript).

We made this wrapper around NaCl, Skein, and Scrypt so we wouldn't have to code review other people's hand-done javascript versions of some complex stuff. Instead, we just use the reference implementations in C and compile it using Emscripten to javascript. As far as we're concerned, this doesn't count as "roll your own crypto."

## Goals

*The goal of this library is to get out of the way.* We merely copy, as faithfully as possible, the awesome work of [the Skein team](https://www.schneier.com/skein-team.html), [Colin Percival (scrypt)](http://www.tarsnap.com/scrypt.html), and [Daniel J. Bernstein (DJB)](http://tweetnacl.cr.yp.to/). All this library tries to accomplish is to call the underlying implementations with as little chance for screw up imaginable. Any excess ceremony should be perceived as a bug and corporal force should be executed against it with extreme prejudice.

## Skein 1024
No big surprises here for you applied crypto folks, but you can do just about anything with one really good pseudo-random function. Thankfully, the Skein team gave us a great one in the SHA-3 competition. Simple and elegant ARX construction, fast on x86/x64, and no huge advantage on an ASIC (compared to Keccak). Since this will end up running on general purpose computers, this is good for us.

Also, a very clean reference implementation like the one sent to NIST gives us a great piece of bedrock upon which to build all the primitives we use in Balboa.

## TweetNaCl
NaCl needs no introduction. Just a great library filled with great crypto primitives. We use the TweetNaCl variant because it is just a lot easier to compile. Furthermore, we use the ed25519 box/open part of NaCl, just a small slice of a really awesome, elegant, and surprisingly developer-friendly API.

## Hash
Skein-1024 PRF with a personalization string.

## HMAC
Skein-1024 PRF with a personalization string, and a key passed to the PRF as well.

## Stream Cipher
Skein-1024 is built around a sweet block cipher, Threefish. We use the 1024 variant, which is pretty gratuitous, but times are tough, and cycles are cheap.

The [Skein-1024 NIST submission paper](http://www.skein-hash.info/sites/default/files/skein1.3.pdf) provides a simple plan for implementing Skein-1024 in a way that essentially makes it Threefish-1024 in counter mode. We do [encrypt then mac](http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/) using our Skein-1024-HMAC inside our Clojurescript. We bundle a randomly generated nonce, the hmac, and the ciphertext together into a Clojure map, and we wanted to avoid weird timing attack potential by doing the HMAC check inside Clojurescript using a timing-safe memcmp.

## PBKDF
Scrypt, plain and simple. Can't do it better. Only twist is we hash the user's password bytes as well as the salt so we can just make everything SKEIN_BLOCK_BYTES in length. We also hash the scrypt output as a simple way of stretching it back to be SKEIN_BLOCK_BYTES. Not adding any security here, but, it is nice to keep the arithmetic really simple.

We use N=15, r=10, p=1. Be careful with these parameters: If you tweak these, you may blow up Emscripten's heap. Easy to fix though, just increase the amount of memory you allocate to the Emscripten heap. Also, pro-tip, don't ALLOW_MEMORY_GROWTH=1 unless you want some pretty dreadful performance hits in the crypto. Give ASM.js a break already.

## Asymmetric Sign+Encrypt
Absolutely nothing special here. We call ED25519 box. We do like the afternm and beforenm calls, since, if you are sending a message to someone once in Balboa, you are likely to send them something else again soon, so we can cache the precomputed key.

## Asymmetric Verify+Decrypt
Absolutely nothing special here. We call ED25519 open. See the above for info about precomputed keys.

## PRNG
Skein-1024-CTR is seeded with our old friend window.crypto.getRandomValues(...). After every call to the PRNG, an additional SKEIN_BLOCK_BYTES is generated, and used to reseed the Skein-1024-CTR. We reseed after every call because we can.

### Gotchas
#### Whoa, why don't the test vectors match? What are you trying to pull here?
They do, you just have to ditch the personalization strings when you call hash.

Balboa uses personalization strings to make sure we don't try to use a hash function from one of our apps in Balboa accidentally, or vice-versa. We like to make sure our PRFs are tied to specific applications. Also, maybe we like to keep secrets from people outside our org for internal applications.

Balboa's personalization strings are inside pkc_skein.h.

#### Hey, wait a sec, this doesn't look like the Skein implementation I downloaded from Skein NIST v1.3.
##### removing dead code
We don't use the Skein-256 or 512 variants, so we took them out. We thought about maybe using Skein-256 instead of SHA-256 inside scrypt, but, we didn't want to scare people with "rolling our own crypto." Run a diff and you'll see we only remove code, except for line 594 of the x86 implementation (see below). 

##### strict aliasing
On line 594 of the x86 implementation, if you compile with -O[1-4] in gcc or -O[1-3] in clang, you'll notice a warning about violating strict aliasing rules. Rather than allowing the cast, and being scared of compiler warnings (don't ever ignore them!), we just decided to swap it out with a gratuitious memcpy. See lines 138-140 of skein.c for details.

### Appendix: The name "trabant"
#### What is a trabant?
We are big fans of freedom of speech and privacy and end-to-end encrypted communications, so, we'll let you fill in the blank on our attitudes towards the Stasi.

![trabant](trabant.jpg)

[Hilarious video on trabants](https://youtu.be/cqWqF56aZtc?t=3m47s)

#### Why name this after a horrible East German car?
Like the trabant itself, we do not want to innovate. We are determined to ride the coat-tails of more brilliant cryptographers forever.
