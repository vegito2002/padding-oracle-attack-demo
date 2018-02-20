package main 

import (
  "io/ioutil"
  "fmt"
  "encoding/hex"
  "flag"
  "os"
)

func main() {
  toHex := flag.Bool ("tohex", true, `a bool, defaults to true, convert the input file to hex if true, convert the input file from hex into readable text if false`)
  inputFile := flag.String ("i", "input.txt", `a string, defaults to input.txt, corresponds to the file that contains human-readable plaintext.`)
  outputFile := flag.String ("o", "plaintext.txt", `a string, defaults to plaintext.txt, corresponds to the name of the file to output hex formatted plaintext`)
  flag.Parse()
  data, err := ioutil.ReadFile (*inputFile)
  if err != nil {
    fmt.Printf ("%s does not exist!\n", *inputFile)
    os.Exit(1)
  }
  var inputText []byte
  if !*toHex {
    inputText = make([]byte, hex.DecodedLen(len(data)))
    hex.Decode(inputText, data)
  } else {
    inputText = data
  }
  var outputText []byte
  if *toHex {
    outputText = make([]byte, hex.EncodedLen(len(inputText)))
    hex.Encode(outputText, inputText)
  } else {
    outputText = inputText
  }
  ioutil.WriteFile(*outputFile, outputText, 0644)
}