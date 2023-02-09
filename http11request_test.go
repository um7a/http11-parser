package http11p

import "testing"

type TestCaseForHttp11RequestMarshal struct {
	testName              string
	data                  []byte
	err                   bool
	expectedMethod        []byte
	expectedRequestTarget []byte
	expectedHttpVersion   []byte
	expectedFieldLines    []FieldLine
	expectedMessageBody   []byte
}

type TestCaseForHttp11RequestUnmarshal struct {
	testName      string
	req           Http11Request
	expectedBytes []byte
}

type TestCaseForHttp11RequestString struct {
	testName    string
	req         Http11Request
	expectedStr string
}

type TestCaseForHttp11RequestGetHeader struct {
	testName           string
	req                Http11Request
	fieldName          string
	expectedFieldValue []byte
}

func execTestForHttp11RequestMarshal(tests []TestCaseForHttp11RequestMarshal, t *testing.T) {
	for _, testCase := range tests {
		t.Run(testCase.testName, func(t *testing.T) {
			var req Http11Request
			err := req.Marshal(testCase.data)

			if err != nil && testCase.err == false {
				t.Errorf("Failed to marshal Http/1.1 Request: %v", err.Error())
				return
			}
			if err == nil && testCase.err == true {
				t.Errorf("Unexpectedly marshal Http/1.1 Request successfully: %v", req)
				return
			}
			if err != nil && testCase.err == true {
				// test success.
				return
			}
			equals := byteEquals(testCase.expectedMethod, req.Method)
			if !equals {
				t.Errorf("expectedMethod: %v, actual: %v",
					testCase.expectedMethod, req.Method)
				return
			}

			equals = byteEquals(testCase.expectedRequestTarget, req.RequestTarget)
			if !equals {
				t.Errorf("expectedRequestTarget: %v, actual: %v",
					testCase.expectedRequestTarget, req.RequestTarget)
				return
			}

			equals = byteEquals(testCase.expectedHttpVersion, req.HttpVersion)
			if !equals {
				t.Errorf("expectedHttpVersion: %v, actual: %v",
					testCase.expectedHttpVersion, req.HttpVersion)
				return
			}

			if len(testCase.expectedFieldLines) != len(req.FieldLines) {
				t.Errorf("len(expectedFieldLines): %v, len(actual): %v",
					len(testCase.expectedFieldLines), len(req.FieldLines))
				return
			}

			for _, expectedfieldLine := range testCase.expectedFieldLines {
				expectedFieldName := expectedfieldLine.FieldName
				expectedFieldValue := expectedfieldLine.FieldValue
				found := false
				for i := 0; i < len(req.FieldLines); i++ {
					actualFieldName := req.FieldLines[i].FieldName
					actualFieldValue := req.FieldLines[i].FieldValue
					if !byteEquals(expectedFieldName, actualFieldName) {
						continue
					}
					if !byteEquals(expectedFieldValue, actualFieldValue) {
						t.Errorf("expected value of \"%v\": %v, actual: %v",
							expectedFieldName, expectedFieldValue, actualFieldValue)
						return
					} else {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("FieldLine of %v not found", expectedFieldName)
					return
				}
			}
		})
	}
}

func execTestForHttp11RequestUnmarshal(tests []TestCaseForHttp11RequestUnmarshal, t *testing.T) {
	for _, testCase := range tests {
		actualBytes := testCase.req.Unmarshal()
		if !byteEquals(testCase.expectedBytes, actualBytes) {
			t.Errorf("expected: %v, actual: %v", testCase.expectedBytes, actualBytes)
			return
		}
	}
}

func execTestForHttp11RequestString(tests []TestCaseForHttp11RequestString, t *testing.T) {
	for _, testCase := range tests {
		actualStr := testCase.req.String()
		if testCase.expectedStr != actualStr {
			t.Errorf("expected: %v, actual: %v", testCase.expectedStr, actualStr)
			return
		}
	}
}

func execTestForHttp11RequestGetHeader(tests []TestCaseForHttp11RequestGetHeader, t *testing.T) {
	for _, testCase := range tests {
		actualFieldValue := testCase.req.GetHeader(testCase.fieldName)
		if !byteEquals(testCase.expectedFieldValue, actualFieldValue) {
			t.Errorf("expected: %v, actual: %v", testCase.expectedFieldValue, actualFieldValue)
			return
		}
	}
}

func TestHttp11RequestMarshal(t *testing.T) {
	tests := []TestCaseForHttp11RequestMarshal{
		{
			testName:              "data: []byte{}",
			data:                  []byte{},
			err:                   true,
			expectedMethod:        []byte{},
			expectedRequestTarget: []byte{},
			expectedHttpVersion:   []byte{},
			expectedFieldLines:    []FieldLine{},
			expectedMessageBody:   []byte{},
		},
		{
			testName: "data: []byte(\"GET /index.html HTTP/1.1\\r\\nCache-Control: no-cache\\r\\nUser-Agent: some-client\\r\\n\\r\\n\")",
			data: []byte(
				"GET /index.html HTTP/1.1\r\n" +
					"Cache-Control: no-cache\r\n" +
					"User-Agent: some-client\r\n" +
					"\r\n",
			),
			err:                   false,
			expectedMethod:        []byte("GET"),
			expectedRequestTarget: []byte("/index.html"),
			expectedHttpVersion:   []byte("HTTP/1.1"),
			expectedFieldLines: []FieldLine{
				{FieldName: []byte("Cache-Control"), FieldValue: []byte("no-cache")},
				{FieldName: []byte("User-Agent"), FieldValue: []byte("some-client")},
			},
			expectedMessageBody: []byte{},
		},
		{
			testName: "data: []byte(\"POST / HTTP/1.1\\r\\nContent-Length: 7\\r\\n\\r\\n\")",
			data: []byte(
				"POST / HTTP/1.1\r\n" +
					"Content-Length: 7\r\n" +
					"\r\n" +
					"abcdefg",
			),
			err:                   false,
			expectedMethod:        []byte("POST"),
			expectedRequestTarget: []byte("/"),
			expectedHttpVersion:   []byte("HTTP/1.1"),
			expectedFieldLines: []FieldLine{
				{FieldName: []byte("Content-Length"), FieldValue: []byte("7")},
			},
			expectedMessageBody: []byte("abcdefg"),
		},
	}
	execTestForHttp11RequestMarshal(tests, t)
}

func TestHttp11RequestUnMarshal(t *testing.T) {
	tests := []TestCaseForHttp11RequestUnmarshal{
		{
			testName: "without body",
			req: Http11Request{
				Method:        []byte("GET"),
				RequestTarget: []byte("/index.html"),
				HttpVersion:   []byte("HTTP/1.1"),
				FieldLines: []FieldLine{
					{
						FieldName:  []byte("Cache-Control"),
						FieldValue: []byte("no-cache"),
					},
				},
			},
			expectedBytes: []byte("GET /index.html HTTP/1.1\r\n" +
				"Cache-Control: no-cache\r\n" +
				"\r\n"),
		},
		{
			testName: "with body",
			req: Http11Request{
				Method:        []byte("POST"),
				RequestTarget: []byte("/"),
				HttpVersion:   []byte("HTTP/1.1"),
				FieldLines: []FieldLine{
					{
						FieldName:  []byte("Content-Length"),
						FieldValue: []byte("7"),
					},
				},
				MessageBody: []byte("abcdefg"),
			},
			expectedBytes: []byte("POST / HTTP/1.1\r\n" +
				"Content-Length: 7\r\n" +
				"\r\n" +
				"abcdefg"),
		},
	}
	execTestForHttp11RequestUnmarshal(tests, t)
}

func TestHttp11RequestString(t *testing.T) {
	tests := []TestCaseForHttp11RequestString{
		{
			testName: "without body",
			req: Http11Request{
				Method:        []byte("GET"),
				RequestTarget: []byte("/index.html"),
				HttpVersion:   []byte("HTTP/1.1"),
				FieldLines: []FieldLine{
					{
						FieldName:  []byte("Cache-Control"),
						FieldValue: []byte("no-cache"),
					},
				},
			},
			expectedStr: "GET /index.html HTTP/1.1\r\n" +
				"Cache-Control: no-cache\r\n" +
				"\r\n",
		},
		{
			testName: "with body",
			req: Http11Request{
				Method:        []byte("POST"),
				RequestTarget: []byte("/"),
				HttpVersion:   []byte("HTTP/1.1"),
				FieldLines: []FieldLine{
					{
						FieldName:  []byte("Content-Length"),
						FieldValue: []byte("7"),
					},
				},
				MessageBody: []byte("abcdefg"),
			},
			expectedStr: "POST / HTTP/1.1\r\n" +
				"Content-Length: 7\r\n" +
				"\r\n" +
				"abcdefg",
		},
	}
	execTestForHttp11RequestString(tests, t)
}

func TestHttp11RequestGetHeader(t *testing.T) {
	tests := []TestCaseForHttp11RequestGetHeader{
		{
			testName: "existing field",
			req: Http11Request{
				Method:        []byte("GET"),
				RequestTarget: []byte("/index.html"),
				HttpVersion:   []byte("HTTP/1.1"),
				FieldLines: []FieldLine{
					{
						FieldName:  []byte("Cache-Control"),
						FieldValue: []byte("no-cache"),
					},
				},
			},
			fieldName:          "Cache-Control",
			expectedFieldValue: []byte("no-cache"),
		},
		{
			testName: "nonexistent header name",
			req: Http11Request{
				Method:        []byte("GET"),
				RequestTarget: []byte("/index.html"),
				HttpVersion:   []byte("HTTP/1.1"),
				FieldLines: []FieldLine{
					{
						FieldName:  []byte("Cache-Control"),
						FieldValue: []byte("no-cache"),
					},
				},
			},
			fieldName:          "Content-Length",
			expectedFieldValue: []byte{},
		},
	}
	execTestForHttp11RequestGetHeader(tests, t)
}
