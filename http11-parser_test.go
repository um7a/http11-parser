package http11p

import (
	"testing"

	abnfp "github.com/um7a/abnf-parser"
)

type TestCase struct {
	testName      string
	data          []byte
	finder        abnfp.Finder
	expectedFound bool
	expectedEnd   int
}

func equals[C comparable](testName string, t *testing.T, expected C, actual C) {
	if actual != expected {
		t.Errorf("%v: expected: %v, actual: %v", testName, expected, actual)
	}
}

func execTest(tests []TestCase, t *testing.T) {
	for _, testCase := range tests {
		t.Run(testCase.testName, func(t *testing.T) {
			found, end := testCase.finder.Find(testCase.data)
			equals(testCase.testName, t, testCase.expectedFound, found)
			equals(testCase.testName, t, testCase.expectedEnd, end)
		})
	}
}

func TestNewUriHostFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewUriHostFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]\")",
			data:          []byte("[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]"),
			finder:        NewUriHostFinder(),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"255.255.255.255\")",
			data:          []byte("255.255.255.255"),
			finder:        NewUriHostFinder(),
			expectedFound: true,
			expectedEnd:   15,
		},
		{
			testName:      "data: []byte(\"www.example.com\")",
			data:          []byte("www.example.com"),
			finder:        NewUriHostFinder(),
			expectedFound: true,
			expectedEnd:   15,
		},
	}
	execTest(tests, t)
}

func TestNewAbsolutePathFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewAbsolutePathFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"path1/path2\")",
			data:          []byte("path1/path2"),
			finder:        NewAbsolutePathFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path1/path2\")",
			data:          []byte("/path1/path2"),
			finder:        NewAbsolutePathFinder(),
			expectedFound: true,
			expectedEnd:   12,
		},
	}
	execTest(tests, t)
}

func TestNewFieldNameFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewFieldNameFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"Content-Length\")",
			data:          []byte("Content-Length"),
			finder:        NewFieldNameFinder(),
			expectedFound: true,
			expectedEnd:   14,
		},
	}
	execTest(tests, t)
}

func TestNewFieldValueFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewFieldValueFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"12\")",
			data:          []byte("12"),
			finder:        NewFieldValueFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
		{
			testName:      "data: []byte(\"12 34\")",
			data:          []byte("12 34"),
			finder:        NewFieldValueFinder(),
			expectedFound: true,
			expectedEnd:   5,
		},
	}
	execTest(tests, t)
}

func TestNewFiledContentFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewFieldContentFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"1\")",
			data:          []byte("1"),
			finder:        NewFieldContentFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"1 2\")",
			data:          []byte("1 2"),
			finder:        NewFieldContentFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte(\"1  2\")",
			data:          []byte("1  2"),
			finder:        NewFieldContentFinder(),
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte(\"12 34\")",
			data:          []byte("12 34"),
			finder:        NewFieldContentFinder(),
			expectedFound: true,
			expectedEnd:   5,
		},
	}
	execTest(tests, t)
}

func TestNewFieldVCharFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewFieldVCharFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{0x20}",
			data:          []byte{0x20},
			finder:        NewFieldVCharFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{0x21}",
			data:          []byte{0x21},
			finder:        NewFieldVCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{0x7e}",
			data:          []byte{0x7e},
			finder:        NewFieldVCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{0x7f}",
			data:          []byte{0x7f},
			finder:        NewFieldVCharFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{0x80}",
			data:          []byte{0x80},
			finder:        NewFieldVCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{0xff}",
			data:          []byte{0xff},
			finder:        NewFieldVCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
	}
	execTest(tests, t)
}

func TestNewObsTextFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewFieldVCharFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{0x7f}",
			data:          []byte{0x7f},
			finder:        NewFieldVCharFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{0x80}",
			data:          []byte{0x80},
			finder:        NewFieldVCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{0xff}",
			data:          []byte{0xff},
			finder:        NewFieldVCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
	}
	execTest(tests, t)
}

func TestNewTokenFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewTokenFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"!\")",
			data:          []byte("!"),
			finder:        NewTokenFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"!#\")",
			data:          []byte("!#"),
			finder:        NewTokenFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
	}
	execTest(tests, t)
}

func TestNewTCharFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewTCharFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"!\")",
			data:          []byte("!"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"#\")",
			data:          []byte("#"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"$\")",
			data:          []byte("$"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"%\")",
			data:          []byte("%"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"&\")",
			data:          []byte("&"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"'\")",
			data:          []byte("'"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"*\")",
			data:          []byte("*"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"+\")",
			data:          []byte("+"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"-\")",
			data:          []byte("-"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\".\")",
			data:          []byte("."),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"^\")",
			data:          []byte("^"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"_\")",
			data:          []byte("_"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"`\")",
			data:          []byte("`"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"|\")",
			data:          []byte("|"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"~\")",
			data:          []byte("~"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"1\")",
			data:          []byte("1"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			finder:        NewTCharFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"(\")",
			data:          []byte("("),
			finder:        NewTCharFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
	}
	execTest(tests, t)
}

func TestNewOwsFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewOwsFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte\" \"",
			data:          []byte(" "),
			finder:        NewOwsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte\"\\t\"",
			data:          []byte("\t"),
			finder:        NewOwsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte\"  \"",
			data:          []byte("  "),
			finder:        NewOwsFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
	}
	execTest(tests, t)
}

func TestNewRwsFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewRwsFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte\" \"",
			data:          []byte(" "),
			finder:        NewRwsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte\"\\t\"",
			data:          []byte("\t"),
			finder:        NewRwsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte\"  \"",
			data:          []byte("  "),
			finder:        NewRwsFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
	}
	execTest(tests, t)
}

func TestNewBwsFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewBwsFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte\" \"",
			data:          []byte(" "),
			finder:        NewBwsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte\"\\t\"",
			data:          []byte("\t"),
			finder:        NewBwsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte\"  \"",
			data:          []byte("  "),
			finder:        NewBwsFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
	}
	execTest(tests, t)
}

func TestNewQuotedStringFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewQuotedStringFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"\\\"a\\\"\")",
			data:          []byte("\"a\""),
			finder:        NewQuotedStringFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte(\"\\\"ab\\\"\")",
			data:          []byte("\"ab\""),
			finder:        NewQuotedStringFinder(),
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte(\"\\\"\\\\ \\\"\")",
			data:          []byte("\"\\ \""), // => "\ "
			finder:        NewQuotedStringFinder(),
			expectedFound: true,
			expectedEnd:   4,
		},
	}
	execTest(tests, t)
}

func TestNewQdTextFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewQdTextFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"\\t\")",
			data:          []byte("\t"),
			finder:        NewQdTextFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\" \")",
			data:          []byte(" "),
			finder:        NewQdTextFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{0x20}",
			data:          []byte{0x20},
			finder:        NewQdTextFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{0x21}",
			data:          []byte{0x21},
			finder:        NewQdTextFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{0x22}",
			data:          []byte{0x22},
			finder:        NewQdTextFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{0x23}",
			data:          []byte{0x23},
			finder:        NewQdTextFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{0x5b}",
			data:          []byte{0x5b},
			finder:        NewQdTextFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{0x5c}",
			data:          []byte{0x5c},
			finder:        NewQdTextFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{0x5d}",
			data:          []byte{0x5b},
			finder:        NewQdTextFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{0x7e}",
			data:          []byte{0x7e},
			finder:        NewQdTextFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{0x7f}",
			data:          []byte{0x7f},
			finder:        NewQdTextFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{0x80}",
			data:          []byte{0x80},
			finder:        NewQdTextFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
	}
	execTest(tests, t)
}

func TestNewQuotePairFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewQuotedPairFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"\\\\t\")",
			data:          []byte("\\\t"),
			finder:        NewQuotedPairFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
		{
			testName:      "data: []byte(\"\\ \")",
			data:          []byte("\\ "),
			finder:        NewQuotedPairFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
		{
			testName:      "data: []byte(\"\\!\")",
			data:          []byte("\\!"),
			finder:        NewQuotedPairFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
		{
			testName:      "data: []byte{'\\', 0x80}",
			data:          []byte{'\\', 0x80},
			finder:        NewQuotedPairFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
	}
	execTest(tests, t)
}

func TestNewHttpMessageFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewHttpMessageFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		// request-line
		{
			testName: "data: []byte(\"GET /index.html HTTP/1.1\\r\\n\\r\\n\")",
			data: []byte(
				"GET /index.html HTTP/1.1\r\n" +
					"\r\n",
			),
			finder:        NewHttpMessageFinder(),
			expectedFound: true,
			expectedEnd:   28,
		},
		// request-line & field-line
		{
			testName: "data: []byte(\"GET /index.html HTTP/1.1\\r\\nCache-Control: no-cache\\r\\n\\r\\n\")",
			data: []byte(
				"GET /index.html HTTP/1.1\r\n" +
					"Cache-Control: no-cache\r\n" +
					"\r\n",
			),
			finder:        NewHttpMessageFinder(),
			expectedFound: true,
			expectedEnd:   53,
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
			finder:        NewHttpMessageFinder(),
			expectedFound: true,
			expectedEnd:   55,
		},
		// status-line
		{
			testName:      "data: []byte(\"HTTP/1.1 200 OK\\r\\n\\r\\n\")",
			data:          []byte("HTTP/1.1 200 OK\r\n\r\n"),
			finder:        NewHttpMessageFinder(),
			expectedFound: true,
			expectedEnd:   19,
		},
		// status-line + field-line
		{
			testName: "data: []byte(\"HTTP/1.1 200 OK\\r\\nCache-Control: no-cache\\r\\n\\r\\n\")",
			data: []byte(
				"HTTP/1.1 200 OK\r\n" + // 17
					"Cache-Control: no-cache\r\n" + // 25
					"\r\n",
			),
			finder:        NewHttpMessageFinder(),
			expectedFound: true,
			expectedEnd:   44,
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
			finder:        NewHttpMessageFinder(),
			expectedFound: true,
			expectedEnd:   45,
		},
	}
	execTest(tests, t)
}

func TestNewStartLineFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewStartLineFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"GET /index.html HTTP/1.1\")",
			data:          []byte("GET /index.html HTTP/1.1"),
			finder:        NewStartLineFinder(),
			expectedFound: true,
			expectedEnd:   24,
		},
		{
			testName:      "data: []byte(\"HTTP/1.1 200 OK\")",
			data:          []byte("HTTP/1.1 200 OK"),
			finder:        NewStartLineFinder(),
			expectedFound: true,
			expectedEnd:   15,
		},
	}
	execTest(tests, t)
}

func TestNewHttpVersionFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewHttpVersionFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"HTTP/1.1\")",
			data:          []byte("HTTP/1.1"),
			finder:        NewHttpVersionFinder(),
			expectedFound: true,
			expectedEnd:   8,
		},
	}
	execTest(tests, t)
}

func TestNewHttpNameFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewHttpNameFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			finder:        NewHttpNameFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"HTTP\")",
			data:          []byte("HTTP"),
			finder:        NewHttpNameFinder(),
			expectedFound: true,
			expectedEnd:   4,
		},
	}
	execTest(tests, t)
}

func TestNewRequestLineFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewRequestLineFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"GET /index.html HTTP/1.1\")",
			data:          []byte("GET /index.html HTTP/1.1"),
			finder:        NewRequestLineFinder(),
			expectedFound: true,
			expectedEnd:   24,
		},
	}
	execTest(tests, t)
}

func TestNewMethodFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewMethodFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			finder:        NewMethodFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"GET\")",
			data:          []byte("GET"),
			finder:        NewMethodFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
	}
	execTest(tests, t)
}

func TestNewRequestTargetFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewRequestTargetFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/index.html\")",
			data:          []byte("/index.html"),
			finder:        NewRequestTargetFinder(),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\"http://example.com/path1/path2?key=value\")",
			data:          []byte("http://example.com/path1/path2?key=value"),
			finder:        NewRequestTargetFinder(),
			expectedFound: true,
			expectedEnd:   40,
		},
		{
			testName:      "data: []byte(\"www.example.com:443\")",
			data:          []byte("www.example.com:443"),
			finder:        NewRequestTargetFinder(),
			expectedFound: true,
			expectedEnd:   19,
		},
		{
			testName:      "data: []byte(\"*\")",
			data:          []byte("*"),
			finder:        NewRequestTargetFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
	}
	execTest(tests, t)
}

func TestNewOriginFormFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewOriginFormFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/index.html\")",
			data:          []byte("/index.html"),
			finder:        NewOriginFormFinder(),
			expectedFound: true,
			expectedEnd:   11,
		},
	}
	execTest(tests, t)
}

func TestNewAbsoluteFormFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewAbsoluteFormFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"http://example.com/path1/path2?key=value\")",
			data:          []byte("http://example.com/path1/path2?key=value"),
			finder:        NewAbsoluteFormFinder(),
			expectedFound: true,
			expectedEnd:   40,
		},
	}
	execTest(tests, t)
}

func TestNewAuthorityFormFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewAuthorityFormFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"www.example.com:443\")",
			data:          []byte("www.example.com:443"),
			finder:        NewAuthorityFormFinder(),
			expectedFound: true,
			expectedEnd:   19,
		},
	}
	execTest(tests, t)
}

func TestNewAsteriskFormFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewAsteriskFormFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"*\")",
			data:          []byte("*"),
			finder:        NewAsteriskFormFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
	}
	execTest(tests, t)
}

func TestNewStatusLineFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewStatusLineFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"HTTP/1.1 200 OK\")",
			data:          []byte("HTTP/1.1 200 OK"),
			finder:        NewStatusLineFinder(),
			expectedFound: true,
			expectedEnd:   15,
		},
	}
	execTest(tests, t)
}

func TestNewStatusCodeFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewStatusCodeFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"200\")",
			data:          []byte("200"),
			finder:        NewStatusCodeFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
	}
	execTest(tests, t)
}

func TestNewReasonPhraseFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewReasonPhraseFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"OK\")",
			data:          []byte("OK"),
			finder:        NewReasonPhraseFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
	}
	execTest(tests, t)
}

func TestNewFieldLineFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewFieldLineFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"Content-Length: 512\")",
			data:          []byte("Content-Length: 100"),
			finder:        NewFieldLineFinder(),
			expectedFound: true,
			expectedEnd:   19,
		},
	}
	execTest(tests, t)
}

func TestNewMessageBodyFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewMessageBodyFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"abc\")",
			data:          []byte("abc"),
			finder:        NewMessageBodyFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
	}
	execTest(tests, t)
}
