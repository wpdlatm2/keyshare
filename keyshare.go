package main

import (
	"fmt"
	//    "io/ioutil"
	"crypto/rand"
	//    "crypto/des"
	"crypto/aes"
	b64 "encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"

	//    "bytes"
	//    "math/rand"
	//    "time"
	"github.com/gorilla/mux"
)

// n bytes to 2*n hex string
func randomHex(n int) (string, error) {
	bytelen := n / 2
	bytes := make([]byte, bytelen)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func xor2byte(key1, key2 []byte) (output []byte) {
	keylen := len(string(key1[:]))
	/*
	   	defer func() {
	   		s := recover()       // recover 함수로 런타임 에러(패닉) 상황을 복구
	   		fmt.Println(s)
	   	}()

	         fmt.Println("KeyLength ", len(string(key1[:])))
	           fmt.Println("Key String ", string(key1[:]))
	           fmt.Println("KeyLength ", len(string(key2[:])))
	           fmt.Println("Key String ", string(key2[:]))
	*/
	b3 := make([]byte, keylen)

	for i := 0; i < keylen; i++ {
		b3[i] = key1[i] ^ key2[i]
	}
	//        fmt.Println("KeyLength ", len(string(b3[:])))
	//        fmt.Println("Key String ", string(b3[:]))
	return b3
}

/*
func aesencrypt(dst, data, key []byte) ([]byte,error) {
	block, err := aes.NewCipher([]byte(key)) // AES 대칭키 암호화 블록 생성
	if err != nil {
		fmt.Println(err)
		return dst,err
	}

	ciphertext := make([]byte, len(data))
	block.Encrypt(ciphertext, []byte(data)) // 평문을 AES 알고리즘으로 암호화
	fmt.Printf("%x\n", ciphertext)

	plaintext := make([]byte, len(data))
	block.Decrypt(plaintext, ciphertext) // AES 알고리즘으로 암호화된 데이터를 평문으로 복호화
	fmt.Println(string(plaintext))
	return ciphertext,nil
}
*/

func KCV(key []byte) (string, error) {
	//	keylen := len(string(key[:]))
	//	kcv := make([]byte, keylen)
	plaintext := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	//	aesencrypt(kcv, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, key)

	block, err := aes.NewCipher([]byte(key)) // AES 대칭키 암호화 블록 생성
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, []byte(plaintext)) // 평문을 AES 알고리즘으로 암호화
	//        fmt.Printf("%x\n", ciphertext)

	kcv := strings.ToUpper(hex.EncodeToString(ciphertext[:3]))

	//	return kcv[:3], strings.ToUpper(hex.EncodeToString(kcv[:3])), nil
	return kcv, nil
}

func hellohandleRequests() {
	myRouter := mux.NewRouter().StrictSlash(true)
	myRouter.HandleFunc("/2component/{Data}", c2)
	//    	myRouter.HandleFunc("/3component/{Data}", c3)
	//    	myRouter.HandleFunc("/mkey2component/{Data}", m2)
	//    	myRouter.HandleFunc("/mkey3component/{Data}", m2)

	http.ListenAndServe(":7484", myRouter)
}

func c2(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	mkeyhex := vars["Data"]
	mkeylen := len(mkeyhex)

	c1hex, _ := randomHex(mkeylen)

	c1ByteArray, err1 := hex.DecodeString(c1hex)
	mkeyByteArray, err2 := hex.DecodeString(mkeyhex)

	mkeyb64 := b64.StdEncoding.EncodeToString([]byte(mkeyByteArray))
	c1b64 := b64.StdEncoding.EncodeToString(c1ByteArray)

	mkeykcv, err3 := KCV(mkeyByteArray)
	c1kcv, err4 := KCV(c1ByteArray)

	fmt.Println("Master Key : ", mkeyhex, mkeylen*8/2, "Bit,", mkeylen, "String(Hex),", "KCV(AES)", mkeykcv)
	//	fmt.Printf("Master Key : %s Bit, %s, %s String(Hex), KCV(AES) %s", mkeylen * 8 / 2, mkeyhex, mkeylen, mkeykcv)
	fmt.Printf("Decoded Byte Array: %v \nDecoded String: %s \n", mkeyByteArray, mkeyByteArray)
	fmt.Printf("Base64 Encoding: %s \n\n", mkeyb64)

	fmt.Println("Component 1 : ", c1hex, len(c1hex)*8/2, "Bit,", len(c1hex), "String(Hex),", "KCV(AES)", c1kcv)
	fmt.Printf("Decoded Byte Array: %v \nDecoded String: %s \n", c1ByteArray, c1ByteArray)
	fmt.Printf("Base64 Encoding: %s \n\n", c1b64)

	c2ByteArray := xor2byte(mkeyByteArray, c1ByteArray)
	c2b64 := b64.StdEncoding.EncodeToString(c2ByteArray)

	c2hex := hex.EncodeToString(c2ByteArray)
	c2kcv, err4 := KCV(c2ByteArray)

	fmt.Println("Component 2 : ", c2hex, len(c2hex)*8/2, "Bit,", len(c2hex), "String(Hex),", "KCV(AES)", c2kcv)
	fmt.Printf("Decoded Byte Array: %v \nDecoded String: %s \n", c2ByteArray, c2ByteArray)
	fmt.Printf("Base64 Encoding: %s \n\n", c2b64)

	//	fmt.Println("Hex String: ", mkeyhex)
	//	fmt.Println("Hex String Length: ", mkeylen)

	//	decodedByteArray, err := hex.DecodeString(mkeyhex)

	if err1 != nil {
		fmt.Println("err1, Unable to convert hex to byte. ", err1)
	}

	if err2 != nil {
		fmt.Println("err2, Unable to convert hex to byte. ", err2)
	}

	if err3 != nil {
		fmt.Println("err3, Unable to convert hex to byte. ", err3)
	}

	if err4 != nil {
		fmt.Println("err4, Unable to convert hex to byte. ", err4)
	}
	/*
			if err5 != nil {
				fmt.Println("err4, Unable to convert hex to byte. ", err5)
		}

	*/
	//	fmt.Printf("Decoded Byte Array: %v \nDecoded String: %s", decodedByteArray, decodedByteArray)
}

func main() {

	hellohandleRequests()
}
