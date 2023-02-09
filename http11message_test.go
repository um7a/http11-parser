package http11p

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
