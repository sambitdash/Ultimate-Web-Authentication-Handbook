module howa.in/chapter-2

go 1.26

require (
	golang.org/x/crypto v0.22.0
	howa.in/common v0.0.0-00010101000000-000000000000
)

require github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect

replace howa.in/common => ../common
