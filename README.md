# Padding Oracle Attack Demo

## Background

[Padding Oracle Attack](https://en.wikipedia.org/wiki/Padding_oracle_attack) is a classic cryptographic attack that shows seemingly complicated security scheme can fall apart really easy. The attack has been carried out in reality (found in TLS and OpenSSL) and and has further variants.

From [Wiki](https://en.wikipedia.org/wiki/Padding_oracle_attack)
> The original attack was published in 2002 by Serge Vaudenay.The attack was applied to several web frameworks, including JavaServer Faces, Ruby on Rails and ASP.NET as well as other software, such as Steam gaming client. In 2012 it was shown to be effective against some hardened security devices.

In this project, I implement from scratch a demonstration of how such an attack is carried out. The highest level of imported library implementation of cryptograph relevant component is AES. All other components including CBC, HMAC etc. are all implemented manually.

The least information you have two know is, an oracle can encrypt your `plaintext` into `ciphertext` with a `key`, or decrypt your `ciphertext` with the same `key` back to the original `plaintext`. A Padding Oracle attacker, with only knowledge of the `ciphertext`, and no knowledge of the `key` used in the encryption, can take advantage of the error message a decrypting oracle outputs to programmatically find out the original `plaintext`. The model of the crypto scheme being attacked is specified as follows (the oracle behaves in such a way):
* The oracle encrypts with classic **tag then encrypt** mode, where we:
    1. Calculate a MAC tag `T` according to HMAC-SHA256 of `M` and the provided MAC key `Mac_key`, append to the original plaintext `M` to get `M' = M || T` (`||` being concatenation).
    2. Calculate padding string `PS` according to [PKCS #5](https://tools.ietf.org/html/rfc2898) scheme. Concatenate again and get `M'' = M' || PS`.
    3. Select a random 16-byte `IV` and encrypt `M''` according to AES-128 in CBC mode: `C' = AES-CBC-ENC (Enc_key, IV, M'')`.
    4. Output `C = IV || C'`.
* During decryption:
    1. Parse `C = IV || C'` to get `IV` and `C'`, then AES-128 CBC decrypt: `M'' = AES-CBC-DEC (Enc_key , IV, C')`.
    2. Validate Padding, output error message **"INVALID PADDING"** and abort if failure.
    3. Parse `M'` as `M || T` because `T` as an HMAC-SHA256 tag is known to be 32-byte long.
    4. Calculate `T'` with `Mac_key` and `M`, then compare with `T`. If different, output error message **"INVALID MAC"** and abort. Otherwise, output the decrypted message `M`. This success can also be views as the oracle outputing error message **"SUCCESS"**.

This cryptographic specification seems solid. It provides both *confidentiality*, *integrity* and *authentication*. But the famous *Padding Oracle Attack* can break such a cryptographic oracle simply by knowing the error message output for each ciphertext query the attacker submits. The basic idea of the attack is introduced [here](https://robertheaton.com/2013/07/29/padding-oracle-attack/).

## Running the Demo
This project consists of two parts. 

### Building the Oracle
In the first part, the program `encrypt-auth` implements the encryption and decryption specification as introduced above. In classic cryptographic vocabulary, we can call such an entity that does encryption or decryption once queried an oracle. 

For generality, both `encrypt-auth` and `decrypt-attack` deals with HEX formatted data primarily. To get the HEX format of a human readable string, as you might want to do to play with the demo, I provide another utility `convert-hex` that can help you convert to or back from HEX format of a string. Store your string in a text file:
```
$ cat string.txt
The original Bitcoin software by Satoshi Nakamoto was released under the MIT license. Most client software, derived or "from scratch", also use open source licensing.

Bitcoin is the first successful implementation of a distributed crypto-currency, described in part in 1998 by Wei Dai on the cypherpunks mailing list. Building upon the notion that money is any object, or any sort of record, accepted as payment for goods and services and repayment of debts in a given country or socio-economic context, Bitcoin is designed around the idea of using cryptography to control the creation and transfer of money, rather than relying on central authorities.

Bitcoins have all the desirable properties of a money-like good. They are portable, durable, divisible, recognizable, fungible, scarce and difficult to counterfeit.
```
Convert to HEX:
```
$ go run convert-hex.go -i string.txt -o plaintext.txt
```
This script takes `-i` to specify the input file, `-o` to specify the output file, and another optional argument `-tohex` to specify that you are converting to or from HEX. This option defaults to `true`. Note that you have to use `-hex=f` to pass in a boolean flag in Go.

Now, you can encrypt:
```
$ go run encrypt-auth.go encrypt -k 69e01355635fd7c8404f823ac591efefea4e0d4b7a72888d46a735149c86f852 -i plaintext.txt -o ciphertext.txt
```
The arguments must be strictly in the order shown above:
* The first argument has to be either `encrypt` or `decrypt` to specify your mode of operation. 
* `-k`: specifies a 32-byte HEX formatted key to be used. The first 16 bytes are `Enc_key` to be used for encryption, while the second 16 bytes the `Mac_key` for MAC calculation. Here, I used `69e01355635fd7c8404f823ac591efefea4e0d4b7a72888d46a735149c86f852` as a demonstration key.
* `-i`: the input file name.
* `-o`: the output file name.

Now, let's decrypt the above file and see if the scheme is correct: the decryption can restore what has been encryted:
```
$ go run encrypt-auth.go decrypt -k 69e01355635fd7c8404f823ac591efefea4e0d4b7a72888d46a735149c86f852 -i ciphertext.txt  -o restore.txt
```
Now the `restore.txt` contains the HEX formatted plaintext. To convert it back to human readable text:
```
$ go run convert-hex.go -tohex=f -i restore.txt -o string-restored.txt
$ diff string-restored.txt string.txt
```
You can open the file and see the original thing.

### Building the Attacker
The attacker knows about the ciphertext from the file `ciphertext.txt`, but knows nothing about the key used. It also has the ability to query the oracle as built above with any ciphertext, making the oracle trying to decrypt it. The oracle will *only* tell the attacker the error information, and nothing about the decrypted information itself, whether write or wrong. Even this limited knowledge of error response can be shown to be much more powerful than anticipated. The attacker can restore the plaintext of the aforementioned intercepted ciphertext simply with this limitted ability, and it never has to find out the key used.

To simulate an oracle that will only return error information, I modified `encrypt-auth` into `decrypt-test`, which has a hard-coded key that we consider the oracle remembers. Such an oracle receives any ciphertext and tries to decrypt it with its stored key, and will only output the error response. The protocol:
```
$ go run decrypt-test.go -i <ciphertext file>
```
This program is compiled into a binary for ease of interaction.

The attacker itself is the program `decrypt-attack` which also takes only one argument of the `<ciphertext file>`:
```
$ go run decrypt-attack.go -i ciphertext.txt -o restored-plaintext.txt
$ go run decrypt-attack.go -i ciphertext.txt
......................................................
$ go run convert-hex.go -tohex=f -i restored-plaintext.txt -o restored-string.txt
$ cat restored-string.txt
The original Bitcoin software by Satoshi Nakamoto was released under the MIT license. Most client software, derived or "from scratch", also use open source licensing.

Bitcoin is the first successful implementation of a distributed crypto-currency, described in part in 1998 by Wei Dai on the cypherpunks mailing list. Building upon the notion that money is any object, or any sort of record, accepted as payment for goods and services and repayment of debts in a given country or socio-economic context, Bitcoin is designed around the idea of using cryptography to control the creation and transfer of money, rather than relying on central authorities.

Bitcoins have all the desirable properties of a money-like good. They are portable, durable, divisible, recognizable, fungible, scarce and difficult to counterfeit.
```
Given only the ciphertext file, will take advantage of `decrypt-test` oracle, and find the actual corresponding plaintext.

## Miscellaneous Notes

The codes are all well-commented. If you are curious about the detailed mechanism of this attack, dig in.

To avoid clutter, all the text files mentioned above, except for `string.txt`(the original human-readable string text) and `test.txt`(the temporary text file used by the `decrypt-attack` program), are all moved into the `texts` folder.

The attacking may take several minutes to finish. There will be dots constantly being printed to the screen to show progress.

TODO: implement a simple website that streamline all the functionalities of this project, including HEX converting, encryption, decrytion, and padding oracle attack.

