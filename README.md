# http11-parser

## Usage

```bash
$ go get github.com/um7a/http11-parser@v0.0.3
```

### Http Request Parser

```go
package main

import (
	"fmt"

	http11p "github.com/um7a/http11-parser"
)

func main() {
	reqData := []byte(
		"POST /path1/path2 HTTP/1.1\r\n" +
		"Content-Length: 7\r\n" +
		"User-Agent: some-client\r\n" +
		"\r\n" +
		"abcdefg",
	)

	var req http11p.Http11Request
	err := req.Marshal(reqData)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Method : %s\n", req.Method)
	fmt.Printf("RequestTarget : %s\n", req.RequestTarget)
	fmt.Printf("HttpVersion: %s\n", req.HttpVersion)
	fmt.Printf("Cache-Control: %s\n", req.GetHeader("Content-Length"))
	fmt.Printf("User-Agent: %s\n", req.GetHeader("User-Agent"))
	fmt.Printf("MessageBody: %s\n", req.MessageBody)
}
```

```bash
$ go run request_parser.go
Method : POST
RequestTarget : /path1/path2
HttpVersion: HTTP/1.1
Cache-Control: 7
User-Agent: some-client
MessageBody: abcdefg
```

### Http Response Parser

```go
package main

import (
	"fmt"

	http11p "github.com/um7a/http11-parser"
)

func main() {
	respData := []byte(
		"HTTP/1.1 200 OK\r\n" +
		"Content-Length: 7\r\n" +
		"\r\n" +
		"abcdefg",
	)

	var resp http11p.Http11Response
	err := resp.Marshal(respData)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("HttpVersion: %s\n", resp.HttpVersion)
	fmt.Printf("StatusCode: %s\n", resp.StatusCode)
	fmt.Printf("ReasonPhrase: %s\n", resp.ReasonPhrase)
	fmt.Printf("Content-Length: %s\n", resp.GetHeader("Content-Length"))
	fmt.Printf("MessageBody: %s\n", resp.MessageBody)
}
```

```bash
$ go run response_parser.go
HttpVersion: HTTP/1.1
StatusCode: 200
ReasonPhrase: OK
Content-Length: 7
MessageBody: abcdefg
```
