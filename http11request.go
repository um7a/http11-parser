package http11p

import (
	"errors"

	abnfp "github.com/um7a/abnf-parser"
)

type Http11Request struct {
	Method        []byte
	RequestTarget []byte
	HttpVersion   []byte
	FieldLines    []FieldLine
	MessageBody   []byte
}

func marshalRequestLine(data []byte, req *Http11Request) (remaining []byte, err error) {
	remaining = data

	result := abnfp.ParseLongest(remaining, FindMethod)
	if len(result.Parsed) == 0 {
		return data, errors.New("method not found")
	}
	req.Method = result.Parsed
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, abnfp.FindSp)
	if len(result.Parsed) == 0 {
		return data, errors.New("SP after method not found")
	}
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, FindRequestTarget)
	if len(result.Parsed) == 0 {
		return data, errors.New("request-target not found")
	}
	req.RequestTarget = result.Parsed
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, abnfp.FindSp)
	if len(result.Parsed) == 0 {
		return data, errors.New("SP after request-target not found")
	}
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, FindHttpVersion)
	if len(result.Parsed) == 0 {
		return data, errors.New("http-version not found")
	}
	req.HttpVersion = result.Parsed
	remaining = result.Remaining

	return
}

func (req *Http11Request) Marshal(data []byte) (err error) {
	var result abnfp.ParseResult
	remaining := data

	remaining, err = marshalRequestLine(remaining, req)
	if err != nil {
		return err
	}

	result = abnfp.ParseShortest(remaining, abnfp.FindCrLf)
	if len(result.Parsed) == 0 {
		return errors.New("CRLF after request-line not found")
	}
	remaining = result.Remaining

	req.FieldLines, remaining, err = marshalFieldLines(remaining)
	if err != nil {
		return err
	}

	result = abnfp.ParseShortest(remaining, abnfp.FindCrLf)
	if len(result.Parsed) == 0 {
		return errors.New("CRLF before message-body not found")
	}
	req.MessageBody = result.Remaining
	return nil
}

func (req Http11Request) Unmarshal() (data []byte) {
	sp := []byte(" ")
	crlf := []byte("\r\n")
	colon := []byte(":")

	data = append(data, req.Method...)
	data = append(data, sp...)
	data = append(data, req.RequestTarget...)
	data = append(data, sp...)
	data = append(data, req.HttpVersion...)
	data = append(data, crlf...)
	for _, fieldLine := range req.FieldLines {
		data = append(data, fieldLine.FieldName...)
		data = append(data, colon...)
		data = append(data, sp...)
		data = append(data, fieldLine.FieldValue...)
		data = append(data, crlf...)
	}
	data = append(data, crlf...)

	data = append(data, req.MessageBody...)
	return
}

func (req Http11Request) String() string {
	bytes := req.Unmarshal()
	return string(bytes)
}

func (req Http11Request) GetHeader(name string) []byte {
	for _, fieldLine := range req.FieldLines {
		if string(fieldLine.FieldName) == name {
			return fieldLine.FieldValue
		}
	}
	return nil
}
