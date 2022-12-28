# keyshare
cipher key share REST API


kakao_bank@BRUCELEE-M-114950 ~ % curl -X POST http://localhost:7484/2component/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFFFF
{"keysize_bit":256,"keysize_byte":32,"keysize_hex":64,"clear_kcv":"337d44","value1":"98a7a0a90d257b30988140e75f8ef5b404bfc9566d41c54b8585c6f9c12d0f46","value1_kcv":"97f200","value2":"320d0a03a78fd19a322bea4df5245f1eae1563fcc7eb6fe12f2f6c536b87f0b9","value2_kcv":"133876"}

kakao_bank@BRUCELEE-M-114950 ~ %




kakao_bank@BRUCELEE-M-114950 ~ % curl -X POST http://localhost:7484/2component/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFFFF -vv
*   Trying 127.0.0.1:7484...
* Connected to localhost (127.0.0.1) port 7484 (#0)
> POST /2component/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFFFF HTTP/1.1
> Host: localhost:7484
> User-Agent: curl/7.79.1
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Content-Type: application/json
< Date: Wed, 28 Dec 2022 11:13:45 GMT
< Content-Length: 272
<
{"keysize_bit":256,"keysize_byte":32,"keysize_hex":64,"clear_kcv":"337d44","value1":"38bcc4a95a4b99751f525568007e6215a5cd311f410162e4265a78b99be474d4","value1_kcv":"4ab270","value2":"92166e03f0e133dfb5f8ffc2aad4c8bf0f679bb5ebabc84e8cf0d213314e8b2b","value2_kcv":"b63f2d"}
* Connection #0 to host localhost left intact

kakao_bank@BRUCELEE-M-114950 ~ %
