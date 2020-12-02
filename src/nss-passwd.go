package main

// #include <pwd.h>
// #include <errno.h>
// #include "nss.h"
// #include <string.h>
import "C"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"unsafe"
)

//export _nss_http_setpwent
func _nss_http_setpwent() C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("_nss_http_setpwent")

	if len(passwdEntries) == 0 {
		resp, err := doRequest("passwd", hostname)
		if err != nil {
			msg := fmt.Sprintf("NSS-HTTP.go: error getting user data: %s\n", err)
			os.Stderr.WriteString(msg)
			return C.NSS_STATUS_UNAVAIL
		}
		if e := json.Unmarshal(resp, &passwdEntries); e != nil {
			msg := fmt.Sprintf("NSS-HTTP.go: error unmarshalling passwd data: %s\n", e)
			os.Stderr.WriteString(msg)
			return C.NSS_STATUS_UNAVAIL
		}
	}

	passwdEntryIndex = 0
	return C.NSS_STATUS_SUCCESS
}

//export _nss_http_endpwent
func _nss_http_endpwent() C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("_nss_http_endpwent")

	passwdEntries = []passwd{}
	passwdEntryIndex = 0
	return C.NSS_STATUS_SUCCESS
}

//export _nss_http_getpwent_r
func _nss_http_getpwent_r(passwd *C.struct_passwd, buf *C.char, buflen C.size_t, errnop *C.int) C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("_nss_http_getpwent_r")

	if len(passwdEntries) == 0 {
		ret := _nss_http_setpwent()
		if ret != C.NSS_STATUS_SUCCESS {
			*errnop = C.ENOENT
			return ret
		}
	}

	if passwdEntryIndex == len(passwdEntries) {
		*errnop = C.ENOENT
		return C.NSS_STATUS_NOTFOUND
	}

	ret := setCPasswd(&passwdEntries[passwdEntryIndex], passwd, buf, buflen, errnop)
	if ret != C.NSS_STATUS_SUCCESS {
		return ret
	}

	passwdEntryIndex++
	return C.NSS_STATUS_SUCCESS
}

//export _nss_http_getpwnam_r
func _nss_http_getpwnam_r(cname *C.char, pwd *C.struct_passwd, buf *C.char, buflen C.size_t, errnop *C.int) C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("_nss_http_getpwnam_r")

	if len(passwdEntries) == 0 {
		ret := _nss_http_setpwent()
		if ret != C.NSS_STATUS_SUCCESS {
			*errnop = C.ENOENT
			return ret
		}
	}

	name := C.GoString(cname)
	for _, p := range passwdEntries {
		if p.Username == name {
			return setCPasswd(&p, pwd, buf, buflen, errnop)
		}
	}

	*errnop = C.ENOENT
	return C.NSS_STATUS_NOTFOUND
}

//export _nss_http_getpwuid_r
func _nss_http_getpwuid_r(uid uint, pwd *C.struct_passwd, buf *C.char, buflen C.size_t, errnop *C.int) C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("_nss_http_getpwuid_r")

	if len(passwdEntries) == 0 {
		ret := _nss_http_setpwent()
		if ret != C.NSS_STATUS_SUCCESS {
			*errnop = C.ENOENT
			return ret
		}
	}

	for _, p := range passwdEntries {
		if p.UID == uid {
			return setCPasswd(&p, pwd, buf, buflen, errnop)
		}
	}

	*errnop = C.ENOENT
	return C.NSS_STATUS_NOTFOUND
}

// set C struct values
func setCPasswd(p *passwd, pwd *C.struct_passwd, buf *C.char, buflen C.size_t, errnop *C.int) C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("setCPasswd")

	if len(p.Username)+len(p.Password)+len(p.Gecos)+len(p.Dir)+len(p.Shell)+5 > int(buflen) {
		*errnop = C.ERANGE
		return C.NSS_STATUS_TRYAGAIN
	}

	gobuf := C.GoBytes(unsafe.Pointer(buf), C.int(buflen))
	b := bytes.NewBuffer(gobuf)
	b.Reset()

	pwd.pw_name = (*C.char)(unsafe.Pointer(&gobuf[b.Len()]))
	b.WriteString(p.Username)
	b.WriteByte(0)

	pwd.pw_passwd = (*C.char)(unsafe.Pointer(&gobuf[b.Len()]))
	b.WriteString(p.Password)
	b.WriteByte(0)

	pwd.pw_gecos = (*C.char)(unsafe.Pointer(&gobuf[b.Len()]))
	b.WriteString(p.Gecos)
	b.WriteByte(0)

	pwd.pw_dir = (*C.char)(unsafe.Pointer(&gobuf[b.Len()]))
	b.WriteString(p.Dir)
	b.WriteByte(0)

	pwd.pw_shell = (*C.char)(unsafe.Pointer(&gobuf[b.Len()]))
	b.WriteString(p.Shell)
	b.WriteByte(0)

	pwd.pw_uid = C.uint(p.UID)
	pwd.pw_gid = C.uint(p.GID)

	return C.NSS_STATUS_SUCCESS
}
