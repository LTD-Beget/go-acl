package acl
// #include <sys/types.h>
// #include <sys/acl.h>
// #cgo LDFLAGS: -lacl
import "C"

type ACL struct {
	ptr C.acl_t
}

type Type C.acl_type_t

const (
	Access  = C.ACL_TYPE_ACCESS
	Default = C.ACL_TYPE_DEFAULT
)

func NewFromString(s string) (self *ACL, e error) {
	cs := C.CString(s)
	ptr, err := C.acl_from_text(cs)
	if err != nil {
		return nil, err
	}
	ret, err := C.acl_valid(ptr)
	if ret != 0 && err != nil {
		return nil, err
	}
	self = &ACL{ ptr: ptr }
	return self, nil
}

func (self *ACL) SetFile(path string, typ Type) (error) {
	cpath := C.CString(path)
	ret, err := C.acl_set_file(cpath, C.acl_type_t(typ), self.ptr)
	if ret != 0 && err != nil {
		return err
	}
	return nil
}

/*
func main() {
	acl, err := NewFromString("u::rw-,u:loggers:r--,g::---,o::---,m::rw-")
	if err != nil {
		fmt.Printf("Error: %v", err)
		return
	}
	err = acl.setFile("test.txt", Access)
	if err != nil {
		fmt.Printf("Error: %v", err)
		return
	}
}
*/
