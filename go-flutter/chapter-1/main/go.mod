module howa.in/chapter-1/main

go 1.26

require (
	github.com/google/uuid v1.6.0
	howa.in/common v0.0.0-00010101000000-000000000000
)

require (
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/crypto v0.22.0 // indirect
)

replace howa.in/common => ../../common
