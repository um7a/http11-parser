package http11p

import (
	"testing"
)

func byteEquals(expected []byte, actual []byte) bool {
	if len(actual) != len(expected) {
		return false
	}
	for i, e := range expected {
		if e != actual[i] {
			return false
		}
	}
	return true
}

func TestMarshalFieldLines(t *testing.T) {
	type TestCaseMarshalFieldLines struct {
		testName           string
		data               []byte
		err                bool
		expectedFieldLines []FieldLine
		expectedRemaining  []byte
	}

	execTest := func(test TestCaseMarshalFieldLines) {
		fieldLines, remaining, err := marshalFieldLines(test.data)
		// Check err
		if err != nil {
			if test.err {
				// success
				return
			}
			t.Errorf("Failed to marshal FieldLines: %v", err.Error())
			return
		}
		if test.err {
			t.Errorf("Unexpectedly marshal FieldLines successfully: %v", fieldLines)
		}

		// Check fieldLines
		if len(test.expectedFieldLines) != len(fieldLines) {
			t.Errorf("expectedFieldLines: %s, actual: %s", test.expectedFieldLines, fieldLines)
		}
		for _, expectedFieldLine := range test.expectedFieldLines {
			has := false
			equals := false
			actualFieldValue := []byte{}
			for _, actualFieldLine := range fieldLines {
				if byteEquals(expectedFieldLine.FieldName, actualFieldLine.FieldName) {
					has = true
					equals = byteEquals(expectedFieldLine.FieldValue, actualFieldLine.FieldValue)
					actualFieldValue = actualFieldLine.FieldValue
					break
				}
			}
			if !has {
				t.Errorf("expected FieldName: %s not found.", expectedFieldLine.FieldName)
				return
			} else if !equals {
				t.Errorf("expected %s: %s, actual: %s.",
					expectedFieldLine.FieldName,
					expectedFieldLine.FieldValue,
					actualFieldValue,
				)
				return
			}
		}
		// Check remaining
		if !byteEquals(test.expectedRemaining, remaining) {
			t.Errorf("expectedRemaining: %s, actual: %s", test.expectedRemaining, remaining)
		}

	}

	tests := []TestCaseMarshalFieldLines{
		{
			testName:           "data: []byte{}",
			data:               []byte{},
			err:                false,
			expectedFieldLines: []FieldLine{},
			expectedRemaining:  []byte{},
		},
		{
			testName: "data: []byte(\"Content-Length: 7\\r\\n\\r\\n\")",
			data:     []byte("Content-Length: 7\r\n\r\n"),
			err:      false,
			expectedFieldLines: []FieldLine{
				{FieldName: []byte("Content-Length"), FieldValue: []byte("7")},
			},
			expectedRemaining: []byte("\r\n"),
		},
		{
			testName: "data: []byte(\"Content-Length: 7\\r\\nConnection: keep-alive\\r\\n\\r\\n\")",
			data:     []byte("Content-Length: 7\r\nConnection: keep-alive\r\n\r\n"),
			err:      false,
			expectedFieldLines: []FieldLine{
				{FieldName: []byte("Content-Length"), FieldValue: []byte("7")},
				{FieldName: []byte("Connection"), FieldValue: []byte("keep-alive")},
			},
			expectedRemaining: []byte("\r\n"),
		},
	}

	for _, test := range tests {
		execTest(test)
	}
}
