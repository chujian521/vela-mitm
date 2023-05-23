package web

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"github.com/andybalholm/brotli"
	"github.com/gorilla/schema"
	log "github.com/sirupsen/logrus"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var OriginMap = map[string]bool{
	"http://172.31.61.150:5173": true,
}

var Param = schema.NewDecoder()

func NewBinMessage(mType messageType, id string, wait int, data []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(byte(messageVersion))
	buf.WriteByte(byte(mType))
	buf.WriteString(id)
	buf.WriteByte(byte(wait))
	buf.Write(data)
	return buf.Bytes()
}

func NewLogonMessage(id string, token string) []byte {
	return NewBinMessage(messageTypeLogin, id, 0, []byte(token))
}

func Unauthorized(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte("not allow"))
	return
}

func Bad(w http.ResponseWriter, code int, format string, v ...interface{}) {
	w.WriteHeader(code)
	w.Write(auxlib.S2B(fmt.Sprintf(format, v...)))
}

func JSON(w http.ResponseWriter, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func Uncompressed(header http.Header, src io.Reader) (string, bool) {
	encoding := header.Get("Content-Encoding")
	switch encoding {
	case "gzip":
		reader, err := gzip.NewReader(src)
		if err != nil {
			log.Error("Failed to create gzip reader:", err)
			break
		}
		defer reader.Close()
		uncompressedBody, err := io.ReadAll(reader)
		if err != nil {
			log.Error("Failed to read uncompressed data:", err)
			break
		}

		return auxlib.B2S(uncompressedBody), true
	case "deflate":
		reader := flate.NewReader(src)
		defer reader.Close()
		uncompressedBody, err := io.ReadAll(reader)
		if err != nil {
			log.Error("Failed to read uncompressed data:", err)
			break
		}

		return auxlib.B2S(uncompressedBody), true
	case "br":
		reader := brotli.NewReader(src)
		uncompressedBody, err := io.ReadAll(reader)
		if err != nil {
			log.Error("Failed to read uncompressed data:", err)
			break
		}
		return auxlib.B2S(uncompressedBody), true
	}

	return "", false
}

func UncompressResponse(r *http.Response) string {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("read body fail %v", err)
		return ""
	}

	if r.Uncompressed {
		return auxlib.B2S(body)
	}

	if len(body) == 0 {
		return ""
	}

	src := bytes.NewReader(body)
	if v, ok := Uncompressed(r.Header, src); ok {
		return v
	}

	return auxlib.B2S(body)
}

func UncompressedBody(header http.Header, body []byte) string {
	if len(body) == 0 {
		return ""
	}

	src := bytes.NewReader(body)
	if v, ok := Uncompressed(header, src); ok {
		return v
	}

	return auxlib.B2S(body)
}

func ReadBody(resp *http.Response) ([]byte, error) {

	var body []byte
	var reader io.ReadCloser
	var err error

	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			goto READER
		}

		defer reader.Close()
		body, err = io.ReadAll(reader)
		if err != nil {
			log.Errorf("gzip decode fail %v", err)
			goto READER
		}
	case "deflate":
		reader, err = zlib.NewReader(resp.Body)
		if err != nil {
			log.Errorf("deflate decode fail %v", err)
			goto READER
		}
		defer reader.Close()

		body, err = io.ReadAll(reader)
		if err != nil {
			goto READER
		}
	}

	if len(body) > 0 {
		return body, nil
	}

READER:
	return io.ReadAll(resp.Body)

}

func RegexMatch(a, b string) bool {
	re := regexp.MustCompile(b)
	if re == nil {
		return false
	}

	match := re.FindAllString(a, -1)
	if len(match) > 0 {
		return true
	}

	return false
}

func ParseCndMethod(v string) (fn func(a, b string) bool, isNot bool) {
	switch v {
	case "equal":
		return func(a, b string) bool { return a == b }, false
	case "!equal":
		return func(a, b string) bool { return a == b }, true

	case "regex":
		return func(a, b string) bool { return a == b }, true

	case "!regex":
		return func(a, b string) bool { return a == b }, true

	case "prefix":
		return strings.HasPrefix, false

	case "!prefix":
		return strings.HasPrefix, true

	case "suffix":
		return strings.HasSuffix, false

	case "!suffix":
		return strings.HasSuffix, true

	case "contain":
		return strings.Contains, false
	case "!contain":
		return strings.Contains, true

	case "ip":

	case "!ip":
	}

	return func(a, b string) bool {
		return false
	}, false

}
