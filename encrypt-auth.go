package main

// test key:
// 69e01355635fd7c8404f823ac591efefea4e0d4b7a72888d46a735149c86f852

import (
  "io/ioutil"
  "fmt"
  "os"
  "encoding/hex"
  "crypto/sha256"
  "crypto/rand"
  "crypto/aes"
  "reflect"
)

//routine for error handling
func check(e error) {
  if e != nil {
    panic(e)
  }
}

func main() {
  args := os.Args[1:]
  // validate command line arguments
  if len(args) != 7 || !(args[0] == "encrypt" || args[0] == "decrypt") || args[1] != "-k" || args[3] != "-i" || args[5] != "-o" || len(args[2]) != 64 {
    fmt.Println(
      `usage: ./encrypt-auth [mode] -k <32-byte-long key in hex representation> -i <input file name> -o <output file name>
      [mode]: encrypt or decrypt
      `)
    os.Exit(1)
  }
  var output []byte
  // choose proper mode: encryption or decryption
  if args[0] == "encrypt" {
    output = encrypt(args)
  } else {
    output = decrypt(args)
  }
  outputToFile := make([]byte, hex.EncodedLen(len(output)))
  hex.Encode(outputToFile, output)
  ioutil.WriteFile(args[6], outputToFile, 0644)
}

/*
Main function that deals with encryption process. Calls into numerous 
subroutines.
Takes as arguments all the command line arguments `args`. Return a byte slice
that can be written into a file.
*/
func encrypt(args []string) []byte {
  keyStr, inputFile := args[2], args[4]
  data, err := ioutil.ReadFile(inputFile)
  check(err)
  if len(data) % 2 != 0 {
    fmt.Println("Invalid plaintext file: octet representation only.")
    os.Exit(1)
  }
  // read in and decode the hex formatted text file
  plaintext := make([]byte, hex.DecodedLen(len(data)))
  _, err = hex.Decode(plaintext, data)
  check(err)
  key := make([]byte, 32)
  _, err = hex.Decode(key, []byte(keyStr))
  // split key
  encKey, macKey := key[:16], key[16:]
  // calculate HMAC on M with `macKey` to get a tag
  hmacTag := hmac(plaintext, macKey)
  // append the tag to the original plaintext message
  plainTextWithTag := append(plaintext, hmacTag...)
  // do the PS padding
  paddedPlainTextWithTag := psPad(plainTextWithTag)
  // do AES CBC mode encryption to get a ciphertext. Return the IV meanwhile
  IV, cipherText := aes_cbc_enc(paddedPlainTextWithTag, encKey)
  // append the ciphertext with IV, and return
  return append(IV, cipherText...)
}

/*
Main function that deals with decryption process. Calls into numerous 
subroutines.
Takes as arguments all the command line arguments `args`. Return a byte slice
that can be written into a file.
*/

func decrypt(args []string) []byte {
  keyStr, inputFile := args[2], args[4]
  data, err := ioutil.ReadFile(inputFile)
  check(err)
  if len(data) % 2 != 0 {
    fmt.Println("Invalid plaintext file: octet representation only.")
    os.Exit(1)
  }
  // read in and decode the hex formatted text file
  cipherTextWithIV := make([]byte, hex.DecodedLen(len(data)))
  _, err = hex.Decode(cipherTextWithIV, data)
  check(err)
  key := make([]byte, 32)
  _, err = hex.Decode(key, []byte(keyStr))
  // split key
  encKey, macKey := key[:16], key[16:]
  // parse C to get C' and IV
  IV, cipherText := cipherTextWithIV[:16], cipherTextWithIV[16:]
  // do the AES CBC decryption first, as in a reverse order from encryption
  plainTextPadded := aes_cbc_dec(cipherText, encKey, IV)
  // remove the PS padding from M'' to get M'
  dePaddedPlainText := stripPadding(plainTextPadded)
  // parse the resultant M' to get the delivered tag T, and the original message
  plainText, tag := dePaddedPlainText[:len(dePaddedPlainText) - 32], 
    dePaddedPlainText[len(dePaddedPlainText) - 32:]
  // Use HMAC to calculate a new Tag on the message
  newTag := hmac(plainText, macKey)
  // Compare with the delivered tag, report error if mismatch
  if !reflect.DeepEqual(tag, newTag) {
    fmt.Println("INVALID MAC")
    os.Exit(1)
  }
  // return the plaintext message if authentication checked out
  return plainText
}

/*
Function that does HMAC. Takes as arguments the input text, and the key used
for this MAC. SHA256 is used as the helper hash function.
*/
func hmac(text []byte, key []byte) []byte {
  B := 64
  // if key is too long, hash it first
  if len(key) > B {
    keyHashed := sha256.Sum256(key)
    key = keyHashed[0:]
  }
  // if key is too short, pad 0x00 to the end first to B-byte length
  if len(key) < B {
    padLen := B - len(key)
    pad := make([]byte, padLen)
    for i := range pad {
      pad[i] = 0
    }
    key = append(key, pad...)
  }
  // tmp1, tmp2, hash1, hash2 are just intermediate values during calculation
  tmp1 := make([]byte, B)
  // xor with ipad first
  for i := range tmp1 {
    tmp1[i] = key[i] ^ 0x36
  }
  // first level hash on the result
  hash1 := sha256.Sum256(append(tmp1, text...))
  tmp1 = hash1[0:]
  tmp2 := make([]byte, B)
  // do a second xor with opad
  for i := range tmp2 {
    tmp2[i] = key[i] ^ 0x5C
  }
  // hash again
  hash2 := sha256.Sum256(append(tmp2, tmp1...))
  return hash2[0:]
}

/*
Function to do the PS padding. Simple logic. Note how you don't really have to
care whether n equals 0 or not.
*/
func psPad(text []byte) []byte {
  n := len(text) % 16
  padding := make([]byte, 16 - n)
  for i := range padding {
    padding[i] = byte(16 - n)
  }
  return append(text, padding...)
}

/*
Do CBC mode encryption on the input `text`, with the key `encKey`. The S-block
used is AES. Returns the encrypted text as well as IV. 
*/
func aes_cbc_enc(text, encKey []byte) ([]byte, []byte) {
  // Get a random IV
  cipherBlock := make([]byte, 16)
  _, err := rand.Read(cipherBlock)
  check(err)
  // `cipherBlock` is a temp value used during calculation. `IV` is used to 
  // store the initial seed
  IV := make([]byte, 16)
  copy(IV, cipherBlock)

  res := make([]byte, len(text))
  // get the AES cipher
  cipher, err := aes.NewCipher(encKey)
  check(err)
  // block by block calculation
  for i := 0; i < len(text) / 16; i++ {
    for j := 0; j < 16; j++ {
      text[i * 16 + j] ^= cipherBlock[j]
    }
    cipher.Encrypt(cipherBlock, text[i * 16 : i * 16 + 16])
    copy(res[i * 16 : i * 16 + 16], cipherBlock)
  }
  return IV, res
}

/*
Do CBC mode decryption on the input `cipherText`, with the key `encKey` and the
`IV`. Returns the decrypted original message. AES is used as the basic block. 
*/
func aes_cbc_dec(cipherText, encKey, IV []byte) []byte {
  // intermediate variable used during calculation. 
  plainBlock := make([]byte, len(IV))
  cipher, err := aes.NewCipher(encKey)
  check(err)
  for i := 0; i < len(cipherText) / 16; i++ {
    copy(plainBlock, cipherText[i * 16 : i * 16 + 16])
    cipher.Decrypt(cipherText[i * 16 : i * 16 + 16], cipherText[i * 16 : i * 16 + 16])
    for j := 0; j < 16; j++ {
      cipherText[i * 16 + j] ^= IV[j]
    }
    copy(IV, plainBlock)
  }
  return cipherText
}

/*
Strips out PS padding. Easy logic: read the last byte to get the padding length,
then go on forward to make sure that the length checks out.
*/
func stripPadding(text []byte) []byte {
  n := len(text)
  padLen := text[n - 1]
  if padLen > 16 {
    fmt.Println("Invalid Padding in Cipher Text, exiting")
    os.Exit(1)
  }
  for i := 2; i <= int(padLen); i++ {
    if text[n - i] != padLen {
      fmt.Println("Invalid Padding in Cipher Text, exiting")
      os.Exit(1)
    }
  }
  return text[:n - int(padLen)]
}