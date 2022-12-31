package main

import (
	"fmt"
	//    "io/ioutil"
	"crypto/rand"
	//    "crypto/des"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	//    "bytes"
	//    "math/rand"
	//    "time"
	"github.com/gorilla/mux"
	"github.com/miekg/pkcs11"
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

func pkcs11random(n int) (string, error) {
	bytelen := n / 2
	//	bytes := make([]byte, n)

	pin := "user"

	// Init PKCS
	//	p := pkcs11.New("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
	p := pkcs11.New("D:\\SoftHSM2\\lib\\softhsm2-x64.dll")
	err := p.Initialize()
	if err != nil {
		panic(err)
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		panic(err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		panic(err)
	}
	defer p.Logout(session)

	/*
		info, err := p.GetInfo()
		if err != nil {
			panic(err)
		}
	*/
	/*
		fmt.Printf("CryptokiVersion.Major %v", info.CryptokiVersion.Major)

		fmt.Println()
	*/

	Randvalue, err := p.GenerateRandom(session, bytelen)
	if err != nil {
		panic(fmt.Sprintf("GenerateRandom() failed %s\n", err))
	}

	/*

			Randvalue_hex := hex.EncodeToString(Randvalue)
			log.Printf("Created Random: %s", Randvalue)
			log.Printf("Created Random: %v", Randvalue)
			log.Printf("Created Random: %s", Randvalue_hex)
		//	log.Printf("Created Random: %v", Randvalue_hex)
	*/
	return hex.EncodeToString(Randvalue), nil

}

func xor2byte(key1, key2 []byte) (output []byte) {
	// 바이트 형태인 key1을 string형식으로 변환하여 키길이를 확인하여 keylen변수에 저장
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

	// 키 길이만큼의 바이트 변수를 생성
	b3 := make([]byte, keylen)

	// key1과 key2값의 키 길이 만큼 각 바이트 어레이를 XOR연산하여 b3에 저장
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

// byte 배열로 key값을 받아서 연산결과를 string 타입과 에러를 반환
func KCV(key []byte) (string, error) {
	//	keylen := len(string(key[:]))
	//	kcv := make([]byte, keylen)

	// 0값으로 채워진 바이트 배열로 평문 plaintext 변수를 생성
	plaintext := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	//	aesencrypt(kcv, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, key)

	// AES 대칭키 암호화 블록 생성
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	// 평문의 길이만큼 암호문을 저장할 바이트 배열 ciphertext 생성
	ciphertext := make([]byte, len(plaintext))

	//	block.Encrypt(ciphertext, []byte(plaintext)) // 평문을 AES 알고리즘으로 암호화

	// 평문을 AES 알고리즘으로 암호화  cipher.block.Encrypt(dst, src)
	block.Encrypt(ciphertext, plaintext) // 평문을 AES 알고리즘으로 암호화
	//        fmt.Printf("%x\n", ciphertext)

	// 암호문의 3바이트를 HEXA DECIMAL 형식의 문자로 변환
	kcv := strings.ToLower(hex.EncodeToString(ciphertext[:3]))

	//	return kcv[:3], strings.ToUpper(hex.EncodeToString(kcv[:3])), nil
	// kcv 값을 문자열 형식으로 반환
	return kcv, nil
}

type Component struct {
	Key_size    int `json:"bit_size"` // 구조체 필드에 태그 지정
	Key_len     int `json:"byte_size"`
	Key_len_hex int `json:"hex_size"`
	//	M_value string `json:"masterkey_value"`
	M_kcv string `json:"clear_kcv"`
	//	M_b64   string `json:"masterkey_base64"`
	C1_value string `json:"value1"`
	C1_kcv   string `json:"value1_kcv"`
	//	C1_b64   string `json:"component1_base64"`
	C2_value string `json:"value2"`
	C2_kcv   string `json:"value2_kcv"`
	// C2_b64   string `json:"component2_base64"`
}

/*
type Key_struct struct {
	Key_type  string
	Key_bit   int
	Key_value string
	Key_kcv   string
	Key_b64   string
}
*/

func C2(rw http.ResponseWriter, req *http.Request) {
	// Content-Type을 json으로 변경
	rw.Header().Add("Content-Type", "application/json")

	// http요청을 vars변수에 저장
	vars := mux.Vars(req)
	// http요청중 Data값을 mkeyhex 변수에 저장
	mkeyhex := vars["Data"]

	mkeylen := len(mkeyhex)
	mkeybyte := mkeylen / 2

	// 컴포넌트1 값은 키길이만큼 랜덤 헥사값을 생성하여 string 변수에 저장
	c1hex, _ := randomHex(mkeylen)
	// 컴포넌트1 값을 입력하면 byte 배열로 반환
	c1ByteArray, err1 := hex.DecodeString(c1hex)
	mkeyByteArray, err2 := hex.DecodeString(mkeyhex)

	// mkeyb64 := b64.StdEncoding.EncodeToString([]byte(mkeyByteArray))
	//	c1b64 := b64.StdEncoding.EncodeToString(c1ByteArray)

	mkeykcv, err3 := KCV(mkeyByteArray)
	c1kcv, err4 := KCV(c1ByteArray)
	mkeybit := mkeylen * 8 / 2

	// c1len := len(c1hex)
	// c1bit := c1len * 8 / 2

	c2ByteArray := xor2byte(mkeyByteArray, c1ByteArray)
	//	c2b64 := b64.StdEncoding.EncodeToString(c2ByteArray)

	c2hex := hex.EncodeToString(c2ByteArray)
	c2kcv, err4 := KCV(c2ByteArray)

	// c2len := len(c2hex)
	// c2bit := c2len * 8 / 2

	req.Header.Set("Content-Type", "application/json")

	//	var Spilt2 = Component{mkeybit, mkeybyte, mkeylen, mkeyhex, mkeykcv, mkeyb64, c1hex, c1kcv, c1b64, c2hex, c2kcv, c2b64}
	var Spilt2 = Component{mkeybit, mkeybyte, mkeylen, mkeykcv, c1hex, c1kcv, c2hex, c2kcv}

	jsonBytes, _ := json.Marshal(Spilt2) // JSON ENCODING
	jsonString := string(jsonBytes)

	fmt.Fprintln(rw, jsonString)

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

type Random struct {
	Randsize_bit  int    `json:"bit_size"`  // 구조체 필드에 태그 지정
	Randsize_byte int    `json:"byte_size"` // 구조체 필드에 태그 지정
	Randsize_hex  int    `json:"hex_size"`  // 구조체 필드에 태그 지정
	Value         string `json:"value"`
}

func OS_random(rw http.ResponseWriter, req *http.Request) {
	// Content-Type을 json으로 변경
	rw.Header().Add("Content-Type", "application/json")

	// http요청을 vars변수에 저장
	vars := mux.Vars(req)
	// http요청중 Data값을 mkeyhex 변수에 저장
	Req_data := vars["Data"]

	// fmt.Println(Req_data)

	// http request로 받은 Data값을 정수로 변환
	Ramdsize_bit, _ := strconv.Atoi(Req_data)
	// bit를 byte단위로 변환
	Randsize_byte := Ramdsize_bit / 8
	// bit를 hexa string단위로 변환
	Randsize_hex := Randsize_byte * 2

	// 컴포넌트1 값은 키길이만큼 랜덤 헥사값을 생성하여 string 변수에 저장
	Rand_value, _ := randomHex(Randsize_hex)

	//	var Spilt2 = Component{mkeybit, mkeybyte, mkeylen, mkeyhex, mkeykcv, mkeyb64, c1hex, c1kcv, c1b64, c2hex, c2kcv, c2b64}
	var Srandom = Random{Ramdsize_bit, Randsize_byte, Randsize_hex, Rand_value}

	jsonBytes, _ := json.Marshal(Srandom) // JSON ENCODING
	jsonString := string(jsonBytes)

	fmt.Fprintln(rw, jsonString)
	/*
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
	*/
	/*
			if err5 != nil {
				fmt.Println("err4, Unable to convert hex to byte. ", err5)
		}
	*/
	//	fmt.Printf("Decoded Byte Array: %v \nDecoded String: %s", decodedByteArray, decodedByteArray)

}

func Secure_random(rw http.ResponseWriter, req *http.Request) {
	// Content-Type을 json으로 변경
	rw.Header().Add("Content-Type", "application/json")

	// http요청을 vars변수에 저장
	vars := mux.Vars(req)
	// http요청중 Data값을 mkeyhex 변수에 저장
	Req_data := vars["Data"]

	// fmt.Println(Req_data)

	// http request로 받은 Data값을 정수로 변환
	Ramdsize_bit, _ := strconv.Atoi(Req_data)
	// bit를 byte단위로 변환
	Randsize_byte := Ramdsize_bit / 8
	// bit를 hexa string단위로 변환
	Randsize_hex := Randsize_byte * 2

	// 컴포넌트1 값은 키길이만큼 랜덤 헥사값을 생성하여 string 변수에 저장
	Rand_value, _ := pkcs11random(Randsize_hex)

	//	var Spilt2 = Component{mkeybit, mkeybyte, mkeylen, mkeyhex, mkeykcv, mkeyb64, c1hex, c1kcv, c1b64, c2hex, c2kcv, c2b64}
	var Srandom = Random{Ramdsize_bit, Randsize_byte, Randsize_hex, Rand_value}

	jsonBytes, _ := json.Marshal(Srandom) // JSON ENCODING
	jsonString := string(jsonBytes)

	fmt.Fprintln(rw, jsonString)
	/*
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
	*/
	/*
			if err5 != nil {
				fmt.Println("err4, Unable to convert hex to byte. ", err5)
		}
	*/
	//	fmt.Printf("Decoded Byte Array: %v \nDecoded String: %s", decodedByteArray, decodedByteArray)

}

type Symkey struct {
	Keyname int `json:"keyname"` // 구조체 필드에 태그 지정
	//	uuid         int    `json:"keyid"`        // 구조체 필드에 태그 지정
	Keyalgo      string `json:"keyalgo"`      // 구조체 필드에 태그 지정
	Keysize_bit  int    `json:"keysize_bit"`  // 구조체 필드에 태그 지정
	Keysize_byte int    `json:"keysize_byte"` // 구조체 필드에 태그 지정
	Keysize_hex  int    `json:"keysize_hex"`  // 구조체 필드에 태그 지정
	Value        string `json:"value"`
	Kcv          string `json:"value_kcv"` // 구조체 필드에 태그 지정
}

type Asmkey struct {
	Keyname int `json:"keyname"` // 구조체 필드에 태그 지정
	//	uuid         int    `json:"keyid"`        // 구조체 필드에 태그 지정
	Keyalgo      string `json:"keyalgo"`      // 구조체 필드에 태그 지정
	Keysize_bit  int    `json:"keysize_bit"`  // 구조체 필드에 태그 지정
	Keysize_byte int    `json:"keysize_byte"` // 구조체 필드에 태그 지정
	Keysize_hex  int    `json:"keysize_hex"`  // 구조체 필드에 태그 지정
	Prv_value    string `json:"value"`
	Pub_value    string `json:"value_pub"`
	Kcv          string `json:"value_kcv"` // 구조체 필드에 태그 지정
}

func Createkey(rw http.ResponseWriter, req *http.Request) {
	// Content-Type을 json으로 변경
	//	rw.Header().Add("Content-Type", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// http요청을 vars변수에 저장
	vars := mux.Vars(req)
	// http요청중 Data값을 mkeyhex 변수에 저장
	Req_data := vars["Data"]

	// http request로 받은 Data값을 정수로 변환
	Ramdsize_bit, _ := strconv.Atoi(Req_data)
	// bit를 byte단위로 변환
	Randsize_byte := Ramdsize_bit / 8
	// bit를 hexa string단위로 변환
	Randsize_hex := Randsize_byte * 2
	/*
		// hex값을 byte값으로 변환
		Randsize_byte := Randsize_hex / 2
		// hex값을 bit단위로 변환
		Ramdsize_bit := Randsize_hex * 8 / 2
	*/
	// 컴포넌트1 값은 키길이만큼 랜덤 헥사값을 생성하여 string 변수에 저장
	Rand_value, _ := randomHex(Randsize_hex)

	//	var Spilt2 = Component{mkeybit, mkeybyte, mkeylen, mkeyhex, mkeykcv, mkeyb64, c1hex, c1kcv, c1b64, c2hex, c2kcv, c2b64}
	var Srandom = Random{Ramdsize_bit, Randsize_byte, Randsize_hex, Rand_value}

	jsonBytes, _ := json.Marshal(Srandom) // JSON ENCODING
	jsonString := string(jsonBytes)

	fmt.Fprintln(rw, jsonString)
	/*
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
	*/
	/*
			if err5 != nil {
				fmt.Println("err4, Unable to convert hex to byte. ", err5)
		}
	*/
	//	fmt.Printf("Decoded Byte Array: %v \nDecoded String: %s", decodedByteArray, decodedByteArray)

}

func hellohandleRequests() {
	// 고릴라먹스를 이용하여 myRouter를 생성
	myRouter := mux.NewRouter().StrictSlash(true)

	//   /2Component/{Data} 형식이 오면 C2 메소드를 실행
	myRouter.HandleFunc("/2component/{Data}", C2)
	//   /2Component/{Data} 형식이 오면 c2 메소드를 실행
	// myRouter.HandleFunc("/3component/{Data}", c3)

	//   /rand 형식이 오면 rand 메소드를 실행
	myRouter.HandleFunc("/rand/{Data}", OS_random)
	myRouter.HandleFunc("/srand/{Data}", Secure_random)

	//   /create 형식이 오면 rand 메소드를 실행
	myRouter.HandleFunc("/create/{Data}/{Bit}/{Begin}/{End}", Createkey)

	/*
		//   /locate/KEYNAME 형식이 오면 locate 메소드를 실행
		myRouter.HandleFunc("/locate/{Data}", Locate)
		//   /get/uuid 형식이 오면 get 메소드를 실행
		myRouter.HandleFunc("/get/{Data}", Get)
		//   /rekey/uuid 형식이 오면 rekey 메소드를 실행
		myRouter.HandleFunc("/rekey/{Data}", Rekey)
		//   /status/uuid 형식이 오면 status 메소드를 실행
		myRouter.HandleFunc("/status/{Data}", Status)
		//   /hash 형식이 오면 hash 메소드를 실행
		myRouter.HandleFunc("/hash/{Data}", Hash)
	*/

	//    	myRouter.HandleFunc("/mkey3component/{Data}", m2)

	http.ListenAndServe(":7484", myRouter)
}

func main() {

	hellohandleRequests()
}
