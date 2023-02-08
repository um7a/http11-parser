package http11p

import (
	"testing"

	abnfp "github.com/um7a/abnf-parser"
)

type TestCase struct {
	testName     string
	data         []byte
	findFunc     abnfp.FindFunc
	expectedEnds []int
}

func fromTo(from int, to int) []int {
	newSlice := []int{}
	for i := from; i <= to; i++ {
		newSlice = append(newSlice, i)
	}
	return newSlice
}

func sliceHasSameElem[C comparable](testName string, t *testing.T, expected []C, actual []C) {
	for _, e := range expected {
		has := false
		for _, a := range actual {
			if e == a {
				has = true
				break
			}
		}
		if !has {
			t.Errorf("%v: actual %v does not have expected element %v", testName, actual, e)
		}
	}
	if len(expected) != len(actual) {
		t.Errorf("%v: expected: %v, actual: %v", testName, expected, actual)
	}
}

func execTest(tests []TestCase, t *testing.T) {
	for _, testCase := range tests {
		t.Run(testCase.testName, func(t *testing.T) {
			actualEnds := testCase.findFunc(testCase.data)
			sliceHasSameElem(testCase.testName, t, testCase.expectedEnds, actualEnds)
		})
	}
}

func TestFindUriHost(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindUriHost,
			expectedEnds: []int{0},
		},
		{
			testName: "data: []byte(\"[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]\")",
			data:     []byte("[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]"),
			findFunc: FindUriHost,
			expectedEnds: []int{
				0,  // "" ==> reg-name
				41, // "[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]" ==> IP-literal
			},
		},
		{
			testName:     "data: []byte(\"255.255.255.255\")",
			data:         []byte("255.255.255.255"),
			findFunc:     FindUriHost,
			expectedEnds: fromTo(0, 15),
			// 0  : "" ==> reg-name
			// 1  : "2" ==> reg-name
			// 2  : "25" ==> reg-name
			// 3  : "255" ==> reg-name
			// 4  : "255." ==> reg-name
			// 5  : "255.2" ==> reg-name
			// 6  : "255.25" ==> reg-name
			// 7  : "255.255" ==> reg-name
			// 8  : "255.255." ==> reg-name
			// 9  : "255.255.2" ==> reg-name
			// 10 : "255.255.25" ==> reg-name
			// 11 : "255.255.255" ==> reg-name
			// 12 : "255.255.255." ==> reg-name
			// 13 : "255.255.255.2" ==> reg-name or IPv4address
			// 14 : "255.255.255.25" ==> reg-name or IPv4address
			// 15 : "255.255.255.255" ==> reg-name or IPv4address
		},
		{
			testName:     "data: []byte(\"www.example.com\")",
			data:         []byte("www.example.com"),
			findFunc:     FindUriHost,
			expectedEnds: fromTo(0, 15),
			// 0  : "" ==> reg-name
			// 1  : "w" ==> reg-name
			// 2  : "ww" ==> reg-name
			// 3  : "www" ==> reg-name
			// 4  : "www." ==> reg-name
			// 5  : "www.e" ==> reg-name
			// 6  : "www.ex" ==> reg-name
			// 7  : "www.exa" ==> reg-name
			// 8  : "www.exam" ==> reg-name
			// 9  : "www.examp" ==> reg-name
			// 10 : "www.exampl" ==> reg-name
			// 11 : "www.example" ==> reg-name
			// 12 : "www.example." ==> reg-name
			// 13 : "www.example.c" ==> reg-name
			// 14 : "www.example.co" ==> reg-name
			// 15 : "www.example.com" ==> reg-name
		},
	}
	execTest(tests, t)
}

func TestFindAbsolutePath(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindAbsolutePath,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"path1/path2\")",
			data:         []byte("path1/path2"),
			findFunc:     FindAbsolutePath,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"/path1/path2\")",
			data:         []byte("/path1/path2"),
			findFunc:     FindAbsolutePath,
			expectedEnds: fromTo(1, 12),
		},
	}
	execTest(tests, t)
}

func TestFindFieldName(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindFieldName,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"Content-Length\")",
			data:         []byte("Content-Length"),
			findFunc:     FindFieldName,
			expectedEnds: fromTo(1, 14),
		},
	}
	execTest(tests, t)
}

func TestFindFieldValue(t *testing.T) {
	tests := []TestCase{
		{
			testName: "data: []byte{}",
			data:     []byte{},
			findFunc: FindFieldValue,
			expectedEnds: []int{
				0,
			},
		},
		{
			testName:     "data: []byte(\"12\")",
			data:         []byte("12"),
			findFunc:     FindFieldValue,
			expectedEnds: fromTo(0, 2),
		},
		{
			testName: "data: []byte(\"12 34\")",
			data:     []byte("12 34"),
			findFunc: FindFieldValue,
			expectedEnds: []int{
				0,
				1,
				2,
				4,
				5,
			},
		},
	}
	execTest(tests, t)
}

func TestFindFiledContent(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindFieldContent,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"1\")",
			data:     []byte("1"),
			findFunc: FindFieldContent,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"1 2\")",
			data:     []byte("1 2"),
			findFunc: FindFieldContent,
			expectedEnds: []int{
				1,
				3,
			},
		},
		{
			testName: "data: []byte(\"1  2\")",
			data:     []byte("1  2"),
			findFunc: FindFieldContent,
			expectedEnds: []int{
				1,
				4,
			},
		},
		{
			testName: "data: []byte(\"12 34\")",
			data:     []byte("12 34"),
			findFunc: FindFieldContent,
			expectedEnds: []int{
				1,
				4,
				5,
			},
		},
	}
	execTest(tests, t)
}

func TestFindFieldVChar(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindFieldVChar,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{0x20}",
			data:         []byte{0x20},
			findFunc:     FindFieldVChar,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte{0x21}",
			data:     []byte{0x21},
			findFunc: FindFieldVChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte{0x7e}",
			data:     []byte{0x7e},
			findFunc: FindFieldVChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName:     "data: []byte{0x7f}",
			data:         []byte{0x7f},
			findFunc:     FindFieldVChar,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte{0x80}",
			data:     []byte{0x80},
			findFunc: FindFieldVChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte{0xff}",
			data:     []byte{0xff},
			findFunc: FindFieldVChar,
			expectedEnds: []int{
				1,
			},
		},
	}
	execTest(tests, t)
}

func TestFindObsText(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindFieldVChar,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{0x7f}",
			data:         []byte{0x7f},
			findFunc:     FindObsText,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte{0x80}",
			data:     []byte{0x80},
			findFunc: FindObsText,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte{0xff}",
			data:     []byte{0xff},
			findFunc: FindObsText,
			expectedEnds: []int{
				1,
			},
		},
	}
	execTest(tests, t)
}

func TestFindToken(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindToken,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"!\")",
			data:     []byte("!"),
			findFunc: FindToken,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"!#\")",
			data:     []byte("!#"),
			findFunc: FindToken,
			expectedEnds: []int{
				1,
				2,
			},
		},
	}
	execTest(tests, t)
}

func TestFindTChar(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindTChar,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"!\")",
			data:     []byte("!"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"#\")",
			data:     []byte("#"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"$\")",
			data:     []byte("$"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"%\")",
			data:     []byte("%"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"&\")",
			data:     []byte("&"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"'\")",
			data:     []byte("'"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"*\")",
			data:     []byte("*"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"+\")",
			data:     []byte("+"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"-\")",
			data:     []byte("-"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\".\")",
			data:     []byte("."),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"^\")",
			data:     []byte("^"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"_\")",
			data:     []byte("_"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"`\")",
			data:     []byte("`"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"|\")",
			data:     []byte("|"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"~\")",
			data:     []byte("~"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"1\")",
			data:     []byte("1"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"a\")",
			data:     []byte("a"),
			findFunc: FindTChar,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName:     "data: []byte(\"(\")",
			data:         []byte("("),
			findFunc:     FindTChar,
			expectedEnds: []int{},
		},
	}
	execTest(tests, t)
}

func TestFindOws(t *testing.T) {
	tests := []TestCase{
		{
			testName: "data: []byte{}",
			data:     []byte{},
			findFunc: FindOws,
			expectedEnds: []int{
				0,
			},
		},
		{
			testName: "data: []byte\" \"",
			data:     []byte(" "),
			findFunc: FindOws,
			expectedEnds: []int{
				0,
				1,
			},
		},
		{
			testName: "data: []byte\"\\t\"",
			data:     []byte("\t"),
			findFunc: FindOws,
			expectedEnds: []int{
				0,
				1,
			},
		},
		{
			testName: "data: []byte\"  \"",
			data:     []byte("  "),
			findFunc: FindOws,
			expectedEnds: []int{
				0,
				1,
				2,
			},
		},
	}
	execTest(tests, t)
}

func TestFindRws(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindRws,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte\" \"",
			data:         []byte(" "),
			findFunc:     FindRws,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte\"\\t\"",
			data:         []byte("\t"),
			findFunc:     FindRws,
			expectedEnds: []int{1},
		},
		{
			testName: "data: []byte\"  \"",
			data:     []byte("  "),
			findFunc: FindRws,
			expectedEnds: []int{
				1,
				2,
			},
		},
	}
	execTest(tests, t)
}

func TestFindBws(t *testing.T) {
	tests := []TestCase{
		{
			testName: "data: []byte{}",
			data:     []byte{},
			findFunc: FindBws,
			expectedEnds: []int{
				0,
			},
		},
		{
			testName: "data: []byte\" \"",
			data:     []byte(" "),
			findFunc: FindBws,
			expectedEnds: []int{
				0,
				1,
			},
		},
		{
			testName: "data: []byte\"\\t\"",
			data:     []byte("\t"),
			findFunc: FindBws,
			expectedEnds: []int{
				0,
				1,
			},
		},
		{
			testName: "data: []byte\"  \"",
			data:     []byte("  "),
			findFunc: FindBws,
			expectedEnds: []int{
				0,
				1,
				2,
			},
		},
	}
	execTest(tests, t)
}

func TestFindQuotedString(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindQuotedString,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"\\\"a\\\"\")",
			data:     []byte("\"a\""),
			findFunc: FindQuotedString,
			expectedEnds: []int{
				3,
			},
		},
		{
			testName: "data: []byte(\"\\\"ab\\\"\")",
			data:     []byte("\"ab\""),
			findFunc: FindQuotedString,
			expectedEnds: []int{
				4,
			},
		},
		{
			testName: "data: []byte(\"\\\"\\\\ \\\"\")",
			data:     []byte("\"\\ \""), // => "\ "
			findFunc: FindQuotedString,
			expectedEnds: []int{
				4,
			},
		},
	}
	execTest(tests, t)
}

func TestFindQdText(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindQdText,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"\\t\")",
			data:     []byte("\t"),
			findFunc: FindQdText,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\" \")",
			data:     []byte(" "),
			findFunc: FindQdText,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte{0x20}",
			data:     []byte{0x20},
			findFunc: FindQdText,
			expectedEnds: []int{
				1, // this is SP
			},
		},
		{
			testName: "data: []byte{0x21}",
			data:     []byte{0x21},
			findFunc: FindQdText,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName:     "data: []byte{0x22}",
			data:         []byte{0x22},
			findFunc:     FindQdText,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte{0x23}",
			data:     []byte{0x23},
			findFunc: FindQdText,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte{0x5b}",
			data:     []byte{0x5b},
			findFunc: FindQdText,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName:     "data: []byte{0x5c}",
			data:         []byte{0x5c},
			findFunc:     FindQdText,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte{0x5d}",
			data:     []byte{0x5b},
			findFunc: FindQdText,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte{0x7e}",
			data:     []byte{0x7e},
			findFunc: FindQdText,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName:     "data: []byte{0x7f}",
			data:         []byte{0x7f},
			findFunc:     FindQdText,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte{0x80}",
			data:     []byte{0x80},
			findFunc: FindQdText,
			expectedEnds: []int{
				1,
			},
		},
	}
	execTest(tests, t)
}

func TestFindQuotePair(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindQuotedPair,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"\\\\t\")",
			data:     []byte("\\\t"),
			findFunc: FindQuotedPair,
			expectedEnds: []int{
				2,
			},
		},
		{
			testName: "data: []byte(\"\\ \")",
			data:     []byte("\\ "),
			findFunc: FindQuotedPair,
			expectedEnds: []int{
				2,
			},
		},
		{
			testName: "data: []byte(\"\\!\")",
			data:     []byte("\\!"),
			findFunc: FindQuotedPair,
			expectedEnds: []int{
				2,
			},
		},
		{
			testName: "data: []byte{'\\', 0x80}",
			data:     []byte{'\\', 0x80},
			findFunc: FindQuotedPair,
			expectedEnds: []int{
				2,
			},
		},
	}
	execTest(tests, t)
}

func TestHttpMessage(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindHttpMessage,
			expectedEnds: []int{},
		},
		// request-line
		{
			testName: "data: []byte(\"GET /index.html HTTP/1.1\\r\\n\\r\\n\")",
			data: []byte(
				"GET /index.html HTTP/1.1\r\n" +
					"\r\n",
			),
			findFunc: FindHttpMessage,
			expectedEnds: []int{
				28,
			},
		},
		// request-line & field-line
		{
			testName: "data: []byte(\"GET /index.html HTTP/1.1\\r\\nCache-Control: no-cache\\r\\n\\r\\n\")",
			data: []byte(
				"GET /index.html HTTP/1.1\r\n" +
					"Cache-Control: no-cache\r\n" +
					"\r\n",
			),
			findFunc: FindHttpMessage,
			expectedEnds: []int{
				53,
			},
		},
		// request-line & field-line & message-body
		{
			testName: "data: []byte(\"GET /index.html HTTP/1.1\\r\\nContent-Length: 7\\r\\n\\r\\nabcdefg\")",
			data: []byte(
				"POST /index.html HTTP/1.1\r\n" +
					"Content-Length: 7\r\n" +
					"\r\n" +
					"abcdefg",
			),
			findFunc:     FindHttpMessage,
			expectedEnds: fromTo(48, 55),
		},
		// status-line
		{
			testName:     "data: []byte(\"HTTP/1.1 200 OK\\r\\n\\r\\n\")",
			data:         []byte("HTTP/1.1 200 OK\r\n\r\n"),
			findFunc:     FindHttpMessage,
			expectedEnds: []int{19},
		},
		// status-line + field-line
		{
			testName: "data: []byte(\"HTTP/1.1 200 OK\\r\\nCache-Control: no-cache\\r\\n\\r\\n\")",
			data: []byte(
				"HTTP/1.1 200 OK\r\n" + // 17
					"Cache-Control: no-cache\r\n" + // 25
					"\r\n",
			),
			findFunc:     FindHttpMessage,
			expectedEnds: []int{44},
		},
		// status-line + field-line + message-body
		{
			testName: "data: []byte(\"HTTP/1.1 200 OK\\r\\nContent-length: 7\\r\\nabcdefg\\r\\n\\r\\n\")",
			data: []byte(
				"HTTP/1.1 200 OK\r\n" + // 17
					"Content-Length: 7\r\n" + // 19
					"\r\n" +
					"abcdefg",
			),
			findFunc:     FindHttpMessage,
			expectedEnds: fromTo(38, 45),
		},
	}
	execTest(tests, t)
}

func TestFindStartLine(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindStartLine,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"GET /index.html HTTP/1.1\")",
			data:     []byte("GET /index.html HTTP/1.1"),
			findFunc: FindRequestLine,
			expectedEnds: []int{
				24,
			},
		},
		{
			testName: "data: []byte(\"HTTP/1.1 200 OK\")",
			data:     []byte("HTTP/1.1 200 OK"),
			findFunc: FindStatusLine,
			expectedEnds: []int{
				13, // "HTTP/1.1 200 "
				14,
				15,
			},
		},
	}
	execTest(tests, t)
}

func TestFindHttpVersion(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindHttpVersion,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"HTTP/1.1\")",
			data:     []byte("HTTP/1.1"),
			findFunc: FindHttpVersion,
			expectedEnds: []int{
				8,
			},
		},
	}
	execTest(tests, t)
}

func TestFindHttpName(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindHttpName,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"a\")",
			data:         []byte("a"),
			findFunc:     FindHttpName,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"HTTP\")",
			data:     []byte("HTTP"),
			findFunc: FindHttpName,
			expectedEnds: []int{
				4,
			},
		},
	}
	execTest(tests, t)
}

func TestFindRequestLine(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindRequestLine,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"GET /index.html HTTP/1.1\")",
			data:     []byte("GET /index.html HTTP/1.1"),
			findFunc: FindRequestLine,
			expectedEnds: []int{
				24,
			},
		},
	}
	execTest(tests, t)
}

func TestFindMethod(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindMethod,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"a\")",
			data:     []byte("a"),
			findFunc: FindMethod,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"GET\")",
			data:     []byte("GET"),
			findFunc: FindMethod,
			expectedEnds: []int{
				1,
				2,
				3,
			},
		},
	}
	execTest(tests, t)
}

func TestFindRequestTarget(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindRequestTarget,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"/index.html\")",
			data:         []byte("/index.html"),
			findFunc:     FindRequestTarget,
			expectedEnds: fromTo(1, 11),
		},
		{
			testName:     "data: []byte(\"http://example.com/path1/path2?key=value\")",
			data:         []byte("http://example.com/path1/path2?key=value"),
			findFunc:     FindRequestTarget,
			expectedEnds: fromTo(5, 40),
			// 5  : "http:" ==> scheme ":" path-empty
			// 6  : "http:/" ==> scheme ":" path-absolute
			// 7  : "http://" ==> scheme ":" "//" authority path-abempty
			// 8  : "http://e"
			// 9  : "http://ex"
			// 10 : "http://exa"
			// 11 : "http://exam"
			// 12 : "http://examp"
			// 13 : "http://exampl"
			// 14 : "http://example"
			// 15 : "http://example."
			// 16 : "http://example.c"
			// 17 : "http://example.co"
			// 18 : "http://example.com"
			// 19 : "http://example.com/"
			// 20 : "http://example.com/p"
			// 21 : "http://example.com/pa"
			// 22 : "http://example.com/pat"
			// 23 : "http://example.com/path"
			// 24 : "http://example.com/path1"
			// 25 : "http://example.com/path1/"
			// 26 : "http://example.com/path1/p"
			// 27 : "http://example.com/path1/pa"
			// 28 : "http://example.com/path1/pat"
			// 29 : "http://example.com/path1/path"
			// 30 : "http://example.com/path1/path2"
			// 31 : "http://example.com/path1/path2?"
			// 32 : "http://example.com/path1/path2?k"
			// 33 : "http://example.com/path1/path2?ke"
			// 34 : "http://example.com/path1/path2?key"
			// 35 : "http://example.com/path1/path2?key="
			// 36 : "http://example.com/path1/path2?key=v"
			// 37 : "http://example.com/path1/path2?key=va"
			// 38 : "http://example.com/path1/path2?key=val"
			// 39 : "http://example.com/path1/path2?key=valu"
			// 40 : "http://example.com/path1/path2?key=value"
		},
		{
			testName: "data: []byte(\"www.example.com:443\")",
			data:     []byte("www.example.com:443"),
			findFunc: FindRequestTarget,
			expectedEnds: []int{
				16, // "www.example.com:"
				17,
				18,
				19,
			},
		},
		{
			testName: "data: []byte(\"*\")",
			data:     []byte("*"),
			findFunc: FindRequestTarget,
			expectedEnds: []int{
				1,
			},
		},
	}
	execTest(tests, t)
}

func TestFindOriginForm(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindOriginForm,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"/index.html\")",
			data:         []byte("/index.html"),
			findFunc:     FindOriginForm,
			expectedEnds: fromTo(1, 11),
		},
	}
	execTest(tests, t)
}

func TestFindAbsoluteForm(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindAbsoluteForm,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"http://example.com/path1/path2?key=value\")",
			data:         []byte("http://example.com/path1/path2?key=value"),
			findFunc:     FindAbsoluteForm,
			expectedEnds: fromTo(5, 40),
			// 5  : "http:" ==> scheme ":" path-empty
			// 6  : "http:/" ==> scheme ":" path-absolute
			// 7  : "http://" ==> scheme ":" "//" authority path-abempty
			// 8  : "http://e"
			// 9  : "http://ex"
			// 10 : "http://exa"
			// 11 : "http://exam"
			// 12 : "http://examp"
			// 13 : "http://exampl"
			// 14 : "http://example"
			// 15 : "http://example."
			// 16 : "http://example.c"
			// 17 : "http://example.co"
			// 18 : "http://example.com"
			// 19 : "http://example.com/"
			// 20 : "http://example.com/p"
			// 21 : "http://example.com/pa"
			// 22 : "http://example.com/pat"
			// 23 : "http://example.com/path"
			// 24 : "http://example.com/path1"
			// 25 : "http://example.com/path1/"
			// 26 : "http://example.com/path1/p"
			// 27 : "http://example.com/path1/pa"
			// 28 : "http://example.com/path1/pat"
			// 29 : "http://example.com/path1/path"
			// 30 : "http://example.com/path1/path2"
			// 31 : "http://example.com/path1/path2?"
			// 32 : "http://example.com/path1/path2?k"
			// 33 : "http://example.com/path1/path2?ke"
			// 34 : "http://example.com/path1/path2?key"
			// 35 : "http://example.com/path1/path2?key="
			// 36 : "http://example.com/path1/path2?key=v"
			// 37 : "http://example.com/path1/path2?key=va"
			// 38 : "http://example.com/path1/path2?key=val"
			// 39 : "http://example.com/path1/path2?key=valu"
			// 40 : "http://example.com/path1/path2?key=value"
		},
	}
	execTest(tests, t)
}

func TestFindAuthorityForm(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindAuthorityForm,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"www.example.com:443\")",
			data:     []byte("www.example.com:443"),
			findFunc: FindAuthorityForm,
			expectedEnds: []int{
				16, // "www.example.com:"
				17,
				18,
				19,
			},
		},
	}
	execTest(tests, t)
}

func TestFindAsteriskForm(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindAsteriskForm,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"*\")",
			data:     []byte("*"),
			findFunc: FindAsteriskForm,
			expectedEnds: []int{
				1,
			},
		},
	}
	execTest(tests, t)
}

func TestFindStatusLine(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindStatusLine,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"HTTP/1.1 200 OK\")",
			data:     []byte("HTTP/1.1 200 OK"),
			findFunc: FindStatusLine,
			expectedEnds: []int{
				13, // "HTTP/1.1 200 "
				14,
				15,
			},
		},
	}
	execTest(tests, t)
}

func TestFindStatusCode(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindStatusCode,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"200\")",
			data:         []byte("200"),
			findFunc:     FindStatusCode,
			expectedEnds: []int{3},
		},
	}
	execTest(tests, t)
}

func TestFindReasonPhrase(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindReasonPhrase,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"OK\")",
			data:     []byte("OK"),
			findFunc: FindReasonPhrase,
			expectedEnds: []int{
				1,
				2,
			},
		},
	}
	execTest(tests, t)
}

func TestFindFieldLine(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindFieldLine,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"Content-Length: 512\")",
			data:     []byte("Content-Length: 100"),
			findFunc: FindFieldLine,
			expectedEnds: []int{
				15,
				16,
				17,
				18,
				19,
			},
		},
	}
	execTest(tests, t)
}

func TestFindMessageBody(t *testing.T) {
	tests := []TestCase{
		{
			testName: "data: []byte{}",
			data:     []byte{},
			findFunc: FindMessageBody,
			expectedEnds: []int{
				0,
			},
		},
		{
			testName: "data: []byte(\"abc\")",
			data:     []byte("abc"),
			findFunc: FindMessageBody,
			expectedEnds: []int{
				0,
				1,
				2,
				3,
			},
		},
	}
	execTest(tests, t)
}
