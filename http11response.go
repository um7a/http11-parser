package http11p

import (
	"errors"

	abnfp "github.com/um7a/abnf-parser"
)

type Http11Response struct {
	HttpVersion  []byte
	StatusCode   []byte
	ReasonPhrase []byte
	FieldLines   []FieldLine
	MessageBody  []byte
}

func marshalStatusLine(data []byte, resp *Http11Response) (remaining []byte, err error) {
	remaining = data

	result := abnfp.ParseLongest(remaining, FindHttpVersion)
	if len(result.Parsed) == 0 {
		return data, errors.New("http-version not found")
	}
	resp.HttpVersion = result.Parsed
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, abnfp.FindSp)
	if len(result.Parsed) == 0 {
		return data, errors.New("SP after http-version not found")
	}
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, FindStatusCode)
	if len(result.Parsed) == 0 {
		return data, errors.New("status-code not found")
	}
	resp.StatusCode = result.Parsed
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, abnfp.FindSp)
	if len(result.Parsed) == 0 {
		return data, errors.New("SP after status-code not found")
	}
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, FindReasonPhrase)
	if len(result.Parsed) == 0 {
		return data, errors.New("reason-phrase not found")
	}
	resp.ReasonPhrase = result.Parsed
	remaining = result.Remaining

	return
}

func (resp *Http11Response) Marshal(data []byte) (err error) {
	var result abnfp.ParseResult
	remaining := data

	remaining, err = marshalStatusLine(remaining, resp)
	if err != nil {
		return err
	}

	result = abnfp.ParseShortest(remaining, abnfp.FindCrLf)
	if len(result.Parsed) == 0 {
		return errors.New("CRLF after request-line not found")
	}
	remaining = result.Remaining

	resp.FieldLines, remaining, err = marshalFieldLines(remaining)
	if err != nil {
		return err
	}

	result = abnfp.ParseShortest(remaining, abnfp.FindCrLf)
	if len(result.Parsed) == 0 {
		return errors.New("CRLF before message-body not found")
	}
	resp.MessageBody = result.Remaining
	return nil
}

func (resp Http11Response) Unmarshal() (data []byte) {
	sp := []byte(" ")
	crlf := []byte("\r\n")
	colon := []byte(":")

	data = append(data, resp.HttpVersion...)
	data = append(data, sp...)
	data = append(data, resp.StatusCode...)
	data = append(data, sp...)
	data = append(data, resp.ReasonPhrase...)
	data = append(data, crlf...)
	for _, fieldLine := range resp.FieldLines {
		data = append(data, fieldLine.FieldName...)
		data = append(data, colon...)
		data = append(data, sp...)
		data = append(data, fieldLine.FieldValue...)
		data = append(data, crlf...)
	}
	data = append(data, crlf...)

	data = append(data, resp.MessageBody...)
	return
}

func (resp Http11Response) String() string {
	bytes := resp.Unmarshal()
	return string(bytes)
}

func (resp Http11Response) GetHeader(name string) []byte {
	for _, fieldLine := range resp.FieldLines {
		if string(fieldLine.FieldName) == name {
			return fieldLine.FieldValue
		}
	}
	return nil
}
