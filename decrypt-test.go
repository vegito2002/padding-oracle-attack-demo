package main

// test key:
// 69e01355635fd7c8404f823ac591efefea4e0d4b7a72888d46a735149c86f852
// test plaintext:
// 4f6620636f757273652c207468697320706172746963756c61722061747461636b20636f756c642062652070726576656e746564206279206361746368696e672074686520657863657074696f6e2c20726174652d6c696d6974696e672072657175657374732066726f6d207468652073616d6520495020616464726573732c206f72206d6f6e69746f72696e6720666f7220737573706963696f75732072657175657374732c206275742074686174201973206f6276696f75736c79206e6f742074686520706f696e742e2041747461636b6572732077696c6c20616c7761797320626520736f70686973746963617465642c20616e642063616e206578706c6f6974206576656e207468652074696e69657374206f6620696d706c656d656e746174696f6e20696d70657266656374696f6e732e204265206361726566756c207769746820796f75722063727970746f2c206576656e207768656e20697420197320736f6d656f6e6520656c736520197321

import (
  "io/ioutil"
  "fmt"
  "os"
  "encoding/hex"
  "crypto/sha256"
  "crypto/aes"
  "reflect"
  "strconv"
  "strings"
)

const keyStr string = 
"69e01355635fd7c8404f823ac591efefea4e0d4b7a72888d46a735149c86f852"

//routine for error handling
func check(e error) {
  if e != nil {
    fmt.Println("Error in decrypt-test")
    panic(e)
  }
}

type MyError string

func (e MyError) Error() string {
  return string(e)
}

func main() {
  args := os.Args[1:]
  // validate command line arguments
  if len(args) != 2 || args[0] != "-i" {
    fmt.Println(
      `usage: ./decrypt-test -i <input file name>`)
    os.Exit(1)
  }
  _, err := decrypt(args)
  if err == nil {
    fmt.Print("SUCCESS")
  } else {
    fmt.Print(err.Error())
  }
}

/*
Main function that deals with decryption process. Calls into numerous 
subroutines.
Takes as arguments all the command line arguments `args`. Return a byte slice
that can be written into a file.
*/

func decrypt(args []string) ([]byte, error) {
  inputFile := args[1]
  data, err := ioutil.ReadFile(inputFile)
  check(err)
  // read in and decode the hex formatted text file
  cipherTextWithIV := make([]byte, hex.DecodedLen(len(data)))
  _, err = hex.Decode(cipherTextWithIV, data)
  if err != nil {
    // ciphertext supplied in decimal format
    tokens := strings.Fields(string(data))
    cipherTextWithIV = make([]byte, len(tokens))
    for i := range tokens {
      val, err := strconv.Atoi(tokens[i])
      check(err)
    cipherTextWithIV[i] = byte(val)
    }
  }
  key := make([]byte, 32)
  _, err = hex.Decode(key, []byte(keyStr))
  // split key
  encKey, macKey := key[:16], key[16:]
  // parse C to get C' and IV
  IV, cipherText := cipherTextWithIV[:16], cipherTextWithIV[16:]
  // do the AES CBC decryption first, as in a reverse order from encryption
  plainTextPadded := aes_cbc_dec(cipherText, encKey, IV)
  // remove the PS padding from M'' to get M'
  dePaddedPlainText, err := stripPadding(plainTextPadded)
  if err != nil {
    return plainTextPadded, err
  }
  // parse the resultant M' to get the delivered tag T, and the original message
  plainText, tag := dePaddedPlainText[:len(dePaddedPlainText) - 32], 
    dePaddedPlainText[len(dePaddedPlainText) - 32:]
  // Use HMAC to calculate a new Tag on the message
  newTag := hmac(plainText, macKey)
  // Compare with the delivered tag, report error if mismatch
  if !reflect.DeepEqual(tag, newTag) {
    return plainText, MyError("INVALID MAC")
  }
  // return the plaintext message if authentication checked out
  return plainText, nil
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
func stripPadding(text []byte) ([]byte, error) {
  n := len(text)
  padLen := text[n - 1]
  if padLen > 16 || padLen == 0 {
    return text, MyError("INVALID PADDING")
  }
  for i := 2; i <= int(padLen); i++ {
    if text[n - i] != padLen {
      return text, MyError("INVALID PADDING")
    }
  }
  return text[:n - int(padLen)], nil
}
