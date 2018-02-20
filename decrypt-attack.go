package main

import (
  "io/ioutil"
  "fmt"
  "os"
  "encoding/hex"
  "crypto/rand"
  "os/exec"
  "strings"
  "strconv"
)

/*
IMPORTANT: READ FIRST
Neither the handout of hw2part1 or hw2part2 gives a hard bound specification 
about the format of ciphertext file, despite specifying the key string and the 
plaintext file to be octet/hexadecimal format. I took the liberty to implement
both my program to be able to handle hexadecimal and decimal format input files.
* hexadecimal: conventional octet string representation
* decimal: space-separated integers

Note that by default, the program operates in hexadecimal mode. The direct 
implication is that your supplied `decrypt-test` program should also take in
hexadecimal format input. If on the other hand, your `decrypt-test` only takes
decimal (space-separated integers) format, do remember to supply the -dec 
command line option to turn on decimal mode.
To turn off hexadecimal mode, or to switch to decimal mode, supply an additional
command line argument -dec as in:
./decrypt-attack -dec -i ciphertextDec.txt

Note that to ensure minimum possibility of bugs, please make sure your decimal
formatted file contains just integers (to represent bytes) and separating spaces.
Certain trimming is done, but it is not comprehensive and failproof.

Algorithm inspired by:
https://robertheaton.com/2013/07/29/padding-oracle-attack/
This is a version that is slightly different from Matthew's approach in class, 
but works well and is easy to scale.
*/

// routine for error handling
func check(e error) {
  if e != nil {
    panic(e)
  }
}

// global flag to store whether hexadecimal or decimal mode in on
var hexMode bool = true

func main() {
  args := os.Args[1:]

  var inputFile string
  // Dirty command line arguments parsing. `flag` package is avoided due to
  // incompatibility with the handout profile specification.
  switch len(args) {
    case 2: {
      if args[0] != "-i" {
        fmt.Println(`usage: ./decrypt-attack [-dec] -i 
          <input ciphertext file>`)
        os.Exit(1)
      }
      inputFile = args[1]
    }
    case 3: {
      // turn on decimal mode operation
      if args[0] != "-dec" || args[1] != "-i" {
        fmt.Println(`usage: ./decrypt-attack [-dec] -i 
          <input ciphertext file>`)
        os.Exit(1)
      }
      inputFile = args[2]
      hexMode = false
    }
    default: {
      fmt.Println(`usage: ./decrypt-attack [-dec] -i 
        <input ciphertext file>`)
      os.Exit(1)
    }
  }

  // read in file into a byte slice
  data, err := ioutil.ReadFile(inputFile)
  check(err)

  // try to decode the file content as hex format first
  cipherTextWithIV := make([]byte, hex.DecodedLen(len(data)))
  _, err = hex.Decode(cipherTextWithIV, data)
  if err != nil {
    // hex decoding failed, that means we have decimal format input file
    tokens := strings.Fields(strings.Trim(strings.TrimSpace(string(data)), 
      "[]{}()\n"))
    cipherTextWithIV = make([]byte, len(tokens))
    for i := range tokens {
      val, err := strconv.Atoi(tokens[i])
      check(err)
      cipherTextWithIV[i] = byte(val)
    }
  }
  
  // parsing the file content into IV and the cipherText
  IV, cipherText := cipherTextWithIV[:16], cipherTextWithIV[16:]
  
  // enforce length limitation of CBC-AES encrypted ciphertext: length must be
  // multiples of block size, which is 16 here
  if len(cipherText) % 16 != 0 {
    fmt.Println("Invalid Input File")
    os.Exit(1)
  }
  guessRes := guess(IV, cipherText)
  padLen := int(guessRes[len(guessRes) - 1])
  res := guessRes[:len(guessRes) - padLen - 32]

  if hexMode {
    fmt.Println(strings.Trim(strings.Join(strings.Fields(fmt.Sprintf("%x", res)), "") , "[]"))
  } else {
    fmt.Println(strings.Trim(fmt.Sprintf("%v", res), "[]"))
  }
}

/*
Main function for the attack. In turn and starting from the tail, copy two 
consecutive blocks to the tail of the ciphertext so that they can be analyzed
with padding oracle attack. Refer to README for more information.
*/
func guess(IV, cipherText []byte) []byte {
  cipherText = append(IV, cipherText...)
  // result buffer
  res := make([]byte, len(cipherText))
  copy(res, cipherText)
  // block number, IV included
  N := len(cipherText) / 16
  // starting from tail, all consecutive block-pairs take turns to be the tail
  // of the ciphertext
  for i := N - 1; i > 0; i-- {
    // Move new block-pair to tail
    copy(cipherText[len(cipherText) - 32: len(cipherText)], 
      res[i * 16 - 16 : i * 16 + 16])
    // Guess the last block using padding oracle attack
    lastBlock := guessLastBlock(cipherText)
    // copy guessed last block into result buffer
    copy(res[i * 16 : i * 16 + 16], lastBlock)
    
    // uncomment this if you want verbose result during attacking
    // ppPrint("finishing res: ", res)///
  }
  // no need to return IV
  return res[16:]
}

/*
Given a (IV||ciphertext), crack it with padding oracle attack, with the aid of
error code/message feedback from `decrypt-test` program.
Refer to README for detailed explanation.
*/
func guessLastBlock(query []byte) []byte {
  /*
  we are trying to crack the I2 = aes-dec(C2), where C2 is the last block of 
  the ciphertext. Note that I2 is then xor-ed with C1, which is the second to
  last block of the ciphertext, to get P2, which is the last byte of the 
  plaintext. As noted in:
  https://robertheaton.com/2013/07/29/padding-oracle-attack/
  I2 is the intermediate state.
  The move here is to use a fake C1, which is named C_1 here, to try for each
  byte of I2, in a way that is similar to Matthew's approach in class.
  Once we have I2 by iterative trying, we can just get P2 = I2 xor C1, which
  is buffered at beginning.
  */

  // Buffer actual C1
  C1 := make([]byte, 16)
  copy(C1, query[len(query) - 32 : len(query) - 16])
  // Result buffer for I2
  I2 := make([]byte, 16)
  // make sure C_1 points to the second to last block of the ciphertext, which
  // is name `query` here because it's to be supplied to external program of 
  // `decrypt-test`
  C_1 := query[len(query) - 32 : len(query) - 16]
  _, err := rand.Read(C_1)
  check(err)
  // try for each byte of the last block, or I2
  for i := 15; i >= 0; i-- {
    padLen := byte(16 - i)
    for j := i + 1; j < 16; j++ {
      C_1[j] = padLen ^ I2[j]
    }

    for k := 0x00; k < 0x100;  {
      // iterate all possible values for this byte of C_1 until it produces 
      // valid padding after xor-ed with I2
      C_1[i] = byte(k)
    
      var outputToFile []byte
      // hexadecimal or decimal mode handling
      if hexMode {
        outputToFile = make([]byte, hex.EncodedLen(len(query)))
        hex.Encode(outputToFile, query)
      } else {
        outputToFile = []byte(strings.Trim(fmt.Sprint(query), "[]"))
      }
      ioutil.WriteFile("test.txt", outputToFile, 0644)      
      
      // delegate to `decrypt-test` program, and get its response message
      out, err := exec.Command("./decrypt-test", "-i", "test.txt").CombinedOutput()
      check(err)

      if !strings.Contains(string(out), "INVALID PADDING") {       
        // We have a valid padding, I2[i] found
        break;
      }
      k++
    }
    // restore I2[i]
    I2[i] = padLen ^ C_1[i]

  }
  // get P2 from I2 and C1
  for i := range I2 {
    I2[i] ^= C1[i]
  }
  return I2
}

/*
This is only a utility function that helps better formatting the bytes during 
development and testing. 
*/
func ppPrint(description string, ar []byte) {
  fmt.Println(description, "length = ", len(ar))
  for i, v := range ar {
    fmt.Printf("%3v ", v)
    if (i + 1) % 16 == 0 {
      fmt.Println()
    }
  }
  fmt.Println()
}