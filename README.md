# keyshare
cipher key share REST API

kakao_bank@BRUCELEE-M-114950 ~ % curl -X POST http://localhost:7484/2component/"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" -vv
*   Trying 127.0.0.1:7484...
* Connected to localhost (127.0.0.1) port 7484 (#0)
> POST /2component/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.1
> Host: localhost:7484
> User-Agent: curl/7.79.1
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Content-Type: application/json
< Date: Tue, 27 Dec 2022 13:10:06 GMT
< Content-Length: 508
<
{"Key_bit":256,"Key_byte":32,"Key_length":64,"Mkey_value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","Mkey_kcv":"D44800","Mkey_b64":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=","C1_value":"433442ab5c7c519259794298e052b265a218e66a36c6ee76770a5ec4d21ba0e4","C1_kcv":"7D20CA","C1_b64":"QzRCq1x8UZJZeUKY4FKyZaIY5mo2xu52dwpexNIboOQ=","C2_value":"e99ee801f6d6fb38f3d3e8324af818cf08b24cc09c6c44dcdda0f46e78b10a4e","C2_kcv":"FE999A","C2_b64":"6Z7oAfbW+zjz0+gySvgYzwiyTMCcbETc3aD0bnixCk4="}
* Connection #0 to host localhost left intact
kakao_bank@BRUCELEE-M-114950 ~ %



kakao_bank@BRUCELEE-M-114950 ~ % curl -X POST http://localhost:7484/2component/"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
{"Key_bit":256,"Key_byte":32,"Key_length":64,"Mkey_value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","Mkey_kcv":"D44800","Mkey_b64":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=","C1_value":"1c686fd0520e10aee0d1c87bcdfe77d052641dbc0a8357a12c99cacd17cff502","C1_kcv":"D4C1C0","C1_b64":"HGhv0FIOEK7g0ch7zf530FJkHbwKg1ehLJnKzRfP9QI=","C2_value":"b6c2c57af8a4ba044a7b62d16754dd7af8ceb716a029fd0b86336067bd655fa8","C2_kcv":"652301","C2_b64":"tsLFevikugRKe2LRZ1TdevjOtxagKf0LhjNgZ71lX6g="}
kakao_bank@BRUCELEE-M-114950 ~ %
