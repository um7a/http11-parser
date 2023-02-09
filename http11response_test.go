package http11p

import "testing"

type TestCaseForHttp11ResponseMarshal struct {
	testName             string
	data                 []byte
	err                  bool
	expectedHttpVersion  []byte
	expectedStatusCode   []byte
	expectedReasonPhrase []byte
	expectedFieldLines   []FieldLine
	expectedMessageBody  []byte
}

type TestCaseForHttp11ResponseUnmarshal struct {
	testName      string
	resp          Http11Response
	expectedBytes []byte
}

type TestCaseForHttp11ResponseString struct {
	testName    string
	resp        Http11Response
	expectedStr string
}

type TestCaseForHttp11ResponseGetHeader struct {
	testName           string
	resp               Http11Response
	fieldName          string
	expectedFieldValue []byte
}

func execTestForHttp11ResponseMarshal(tests []TestCaseForHttp11ResponseMarshal, t *testing.T) {
	for _, testCase := range tests {
		t.Run(testCase.testName, func(t *testing.T) {
			var resp Http11Response
			err := resp.Marshal(testCase.data)

			if err != nil && testCase.err == false {
				t.Errorf("Failed to marshal Http/1.1 Response: %v", err.Error())
				return
			}
			if err == nil && testCase.err == true {
				t.Errorf("Unexpectedly marshal Http/1.1 Response successfully: %v", resp)
				return
			}
			if err != nil && testCase.err == true {
				// test success.
				return
			}

			equals := byteEquals(testCase.expectedHttpVersion, resp.HttpVersion)
			if !equals {
				t.Errorf("expectedHttpVersion: %v, actual: %v",
					testCase.expectedHttpVersion, resp.HttpVersion)
				return
			}

			equals = byteEquals(testCase.expectedStatusCode, resp.StatusCode)
			if !equals {
				t.Errorf("expectedStatusCode: %v, actual: %v",
					testCase.expectedStatusCode, resp.StatusCode)
				return
			}

			equals = byteEquals(testCase.expectedReasonPhrase, resp.ReasonPhrase)
			if !equals {
				t.Errorf("expectedReasonPhrase: %v, actual: %v",
					testCase.expectedReasonPhrase, resp.ReasonPhrase)
				return
			}

			if len(testCase.expectedFieldLines) != len(resp.FieldLines) {
				t.Errorf("len(expectedFieldLines): %v, len(actual): %v",
					len(testCase.expectedFieldLines), len(resp.FieldLines))
				return
			}

			for _, expectedfieldLine := range testCase.expectedFieldLines {
				expectedFieldName := expectedfieldLine.FieldName
				expectedFieldValue := expectedfieldLine.FieldValue
				found := false
				for i := 0; i < len(resp.FieldLines); i++ {
					actualFieldName := resp.FieldLines[i].FieldName
					actualFieldValue := resp.FieldLines[i].FieldValue
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

func execTestForHttp11ResponseUnmarshal(tests []TestCaseForHttp11ResponseUnmarshal, t *testing.T) {
	for _, testCase := range tests {
		actualBytes := testCase.resp.Unmarshal()
		if !byteEquals(testCase.expectedBytes, actualBytes) {
			t.Errorf("expected: %v, actual: %v", testCase.expectedBytes, actualBytes)
			return
		}
	}
}

func execTestForHttp11ResponseString(tests []TestCaseForHttp11ResponseString, t *testing.T) {
	for _, testCase := range tests {
		actualStr := testCase.resp.String()
		if testCase.expectedStr != actualStr {
			t.Errorf("expected: %v, actual: %v", testCase.expectedStr, actualStr)
			return
		}
	}
}

func execTestForHttp11ResponseGetHeader(tests []TestCaseForHttp11ResponseGetHeader, t *testing.T) {
	for _, testCase := range tests {
		actualFieldValue := testCase.resp.GetHeader(testCase.fieldName)
		if !byteEquals(testCase.expectedFieldValue, actualFieldValue) {
			t.Errorf("expected: %v, actual: %v", testCase.expectedFieldValue, actualFieldValue)
			return
		}
	}
}

func TestHttp11ResponseMarshal(t *testing.T) {
	tests := []TestCaseForHttp11ResponseMarshal{
		{
			testName:             "data: []byte{}",
			data:                 []byte{},
			err:                  true,
			expectedHttpVersion:  []byte{},
			expectedStatusCode:   []byte{},
			expectedReasonPhrase: []byte{},
			expectedFieldLines:   []FieldLine{},
			expectedMessageBody:  []byte{},
		},
		{
			testName: "data: []byte(\"HTTP/1.1 200 OK\\r\\nContent-Length: 7\\r\\n\\r\\nabcdefg\")",
			data: []byte(
				"HTTP/1.1 200 OK\r\n" +
					"Content-Length: 7\r\n" +
					"\r\n" +
					"abcdefg",
			),
			err:                  false,
			expectedHttpVersion:  []byte("HTTP/1.1"),
			expectedStatusCode:   []byte("200"),
			expectedReasonPhrase: []byte("OK"),
			expectedFieldLines: []FieldLine{
				{FieldName: []byte("Content-Length"), FieldValue: []byte("7")},
			},
			expectedMessageBody: []byte("abcdefg"),
		},
		{
			testName: "data: []byte(\"HTTP/1.1 204 No Content\\r\\n\\r\\n\")",
			data: []byte(
				"HTTP/1.1 204 No Content\r\n" +
					"\r\n",
			),
			err:                  false,
			expectedHttpVersion:  []byte("HTTP/1.1"),
			expectedStatusCode:   []byte("204"),
			expectedReasonPhrase: []byte("No Content"),
			expectedFieldLines:   []FieldLine{},
			expectedMessageBody:  []byte{},
		},
	}
	execTestForHttp11ResponseMarshal(tests, t)
}

func TestHttp11ResponseUnMarshal(t *testing.T) {
	tests := []TestCaseForHttp11ResponseUnmarshal{
		{
			testName: "without body",
			resp: Http11Response{
				HttpVersion:  []byte("HTTP/1.1"),
				StatusCode:   []byte("204"),
				ReasonPhrase: []byte("No Content"),
				FieldLines:   []FieldLine{},
				MessageBody:  []byte{},
			},
			expectedBytes: []byte(
				"HTTP/1.1 204 No Content\r\n" +
					"\r\n",
			),
		},
		{
			testName: "with body",
			resp: Http11Response{
				HttpVersion:  []byte("HTTP/1.1"),
				StatusCode:   []byte("200"),
				ReasonPhrase: []byte("OK"),
				FieldLines: []FieldLine{
					{
						FieldName:  []byte("Content-Length"),
						FieldValue: []byte("7"),
					},
				},
				MessageBody: []byte("abcdefg"),
			},
			expectedBytes: []byte(
				"HTTP/1.1 200 OK\r\n" +
					"Content-Length: 7\r\n" +
					"\r\n" +
					"abcdefg",
			),
		},
	}
	execTestForHttp11ResponseUnmarshal(tests, t)
}

func TestHttp11ResponseString(t *testing.T) {
	tests := []TestCaseForHttp11ResponseString{
		{
			testName: "without body",
			resp: Http11Response{
				HttpVersion:  []byte("HTTP/1.1"),
				StatusCode:   []byte("204"),
				ReasonPhrase: []byte("No Content"),
				FieldLines:   []FieldLine{},
				MessageBody:  []byte{},
			},
			expectedStr: "HTTP/1.1 204 No Content\r\n" +
				"\r\n",
		},
		{
			testName: "with body",
			resp: Http11Response{
				HttpVersion:  []byte("HTTP/1.1"),
				StatusCode:   []byte("200"),
				ReasonPhrase: []byte("OK"),
				FieldLines: []FieldLine{
					{
						FieldName:  []byte("Content-Length"),
						FieldValue: []byte("7"),
					},
				},
				MessageBody: []byte("abcdefg"),
			},
			expectedStr: "HTTP/1.1 200 OK\r\n" +
				"Content-Length: 7\r\n" +
				"\r\n" +
				"abcdefg",
		},
	}
	execTestForHttp11ResponseString(tests, t)
}

func TestHttp11ResponseGetHeader(t *testing.T) {
	tests := []TestCaseForHttp11ResponseGetHeader{
		{
			testName: "existing field",
			resp: Http11Response{
				HttpVersion:  []byte("HTTP/1.1"),
				StatusCode:   []byte("200"),
				ReasonPhrase: []byte("OK"),
				FieldLines: []FieldLine{
					{
						FieldName:  []byte("Content-Length"),
						FieldValue: []byte("7"),
					},
				},
				MessageBody: []byte("abcdefg"),
			},
			fieldName:          "Content-Length",
			expectedFieldValue: []byte("7"),
		},
		{
			testName: "nonexistent field",
			resp: Http11Response{
				HttpVersion:  []byte("HTTP/1.1"),
				StatusCode:   []byte("200"),
				ReasonPhrase: []byte("OK"),
				FieldLines: []FieldLine{
					{
						FieldName:  []byte("Content-Length"),
						FieldValue: []byte("7"),
					},
				},
				MessageBody: []byte("abcdefg"),
			},
			fieldName:          "CacheControl",
			expectedFieldValue: []byte{},
		},
	}
	execTestForHttp11ResponseGetHeader(tests, t)
}
