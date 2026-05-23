package dht

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
)

// encode serialises a value to bencode. Supported types:
//   string  → <len>:<bytes>   (raw; may contain binary data)
//   []byte  → <len>:<bytes>
//   int     → i<n>e
//   int64   → i<n>e
//   []any   → l...e
//   map[string]any → d...e  (keys sorted lexicographically per BEP 3)
func encode(v any) []byte {
	var buf bytes.Buffer
	encodeInto(&buf, v)
	return buf.Bytes()
}

func encodeInto(buf *bytes.Buffer, v any) {
	switch x := v.(type) {
	case string:
		buf.WriteString(strconv.Itoa(len(x)))
		buf.WriteByte(':')
		buf.WriteString(x)
	case []byte:
		buf.WriteString(strconv.Itoa(len(x)))
		buf.WriteByte(':')
		buf.Write(x)
	case int:
		fmt.Fprintf(buf, "i%de", x)
	case int64:
		fmt.Fprintf(buf, "i%de", x)
	case []any:
		buf.WriteByte('l')
		for _, item := range x {
			encodeInto(buf, item)
		}
		buf.WriteByte('e')
	case map[string]any:
		buf.WriteByte('d')
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			encodeInto(buf, k)
			encodeInto(buf, x[k])
		}
		buf.WriteByte('e')
	}
}

// decode parses one bencode value from data and returns it plus how many
// bytes were consumed. Return types:
//
//	byte string → string  (may contain binary data; callers cast to []byte as needed)
//	integer     → int64
//	list        → []any
//	dict        → map[string]any
func decode(data []byte) (any, int, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("bencode: empty input")
	}
	switch {
	case data[0] == 'i':
		end := bytes.IndexByte(data, 'e')
		if end < 0 {
			return nil, 0, fmt.Errorf("bencode: unterminated integer")
		}
		n, err := strconv.ParseInt(string(data[1:end]), 10, 64)
		return n, end + 1, err

	case data[0] == 'l':
		var items []any
		i := 1
		for i < len(data) {
			if data[i] == 'e' {
				return items, i + 1, nil
			}
			v, n, err := decode(data[i:])
			if err != nil {
				return nil, 0, err
			}
			items = append(items, v)
			i += n
		}
		return nil, 0, fmt.Errorf("bencode: unterminated list")

	case data[0] == 'd':
		m := make(map[string]any)
		i := 1
		for i < len(data) {
			if data[i] == 'e' {
				return m, i + 1, nil
			}
			kv, n, err := decode(data[i:])
			if err != nil {
				return nil, 0, err
			}
			key, ok := kv.(string)
			if !ok {
				return nil, 0, fmt.Errorf("bencode: dict key is not a string")
			}
			i += n
			v, n, err := decode(data[i:])
			if err != nil {
				return nil, 0, err
			}
			m[key] = v
			i += n
		}
		return nil, 0, fmt.Errorf("bencode: unterminated dict")

	default: // byte string: <len>:<bytes>
		colon := bytes.IndexByte(data, ':')
		if colon < 0 {
			return nil, 0, fmt.Errorf("bencode: no colon in string")
		}
		length, err := strconv.Atoi(string(data[:colon]))
		if err != nil || length < 0 {
			return nil, 0, fmt.Errorf("bencode: invalid string length")
		}
		start := colon + 1
		end := start + length
		if end > len(data) {
			return nil, 0, fmt.Errorf("bencode: string data truncated")
		}
		return string(data[start:end]), end, nil
	}
}
