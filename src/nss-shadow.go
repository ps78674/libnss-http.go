package main

// #include <shadow.h>
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

//export _nss_http_setspent
func _nss_http_setspent() C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("_nss_http_setspent")

	if len(shadowEntries) == 0 {
		resp, err := doRequest("shadow", hostname)
		if err != nil {
			msg := fmt.Sprintf("NSS-HTTP.go: error getting user data: %s\n", err)
			os.Stderr.WriteString(msg)
			return C.NSS_STATUS_UNAVAIL
		}
		if e := json.Unmarshal(resp, &shadowEntries); e != nil {
			msg := fmt.Sprintf("NSS-HTTP.go: error unmarshalling shadow data: %s\n", e)
			os.Stderr.WriteString(msg)
			return C.NSS_STATUS_UNAVAIL
		}
	}

	shadowEntryIndex = 0
	return C.NSS_STATUS_SUCCESS
}

//export _nss_http_endspent
func _nss_http_endspent() C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("_nss_http_endspent")

	shadowEntries = []shadow{}
	shadowEntryIndex = 0
	return C.NSS_STATUS_SUCCESS
}

//export _nss_http_getspent_r
func _nss_http_getspent_r(spwd *C.struct_spwd, buf *C.char, buflen C.size_t, errnop *C.int) C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("_nss_http_getspent_r")

	if len(shadowEntries) == 0 {
		ret := _nss_http_setspent()
		if ret != C.NSS_STATUS_SUCCESS {
			*errnop = C.ENOENT
			return ret
		}
	}

	if shadowEntryIndex == len(shadowEntries) {
		*errnop = C.ENOENT
		return C.NSS_STATUS_NOTFOUND
	}

	ret := setCShadow(&shadowEntries[shadowEntryIndex], spwd, buf, buflen, errnop)
	if ret != C.NSS_STATUS_SUCCESS {
		return ret
	}

	shadowEntryIndex++
	return C.NSS_STATUS_SUCCESS
}

//export _nss_http_getspnam_r
func _nss_http_getspnam_r(cname *C.char, spwd *C.struct_spwd, buf *C.char, buflen C.size_t, errnop *C.int) C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("_nss_http_getspnam_r")

	if len(shadowEntries) == 0 {
		ret := _nss_http_setspent()
		if ret != C.NSS_STATUS_SUCCESS {
			*errnop = C.ENOENT
			return ret
		}
	}

	name := C.GoString(cname)
	for _, s := range shadowEntries {
		if s.Username == name {
			return setCShadow(&s, spwd, buf, buflen, errnop)
		}

	}

	*errnop = C.ENOENT
	return C.NSS_STATUS_NOTFOUND
}

// set C struct values
func setCShadow(p *shadow, spwd *C.struct_spwd, buf *C.char, buflen C.size_t, errnop *C.int) C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("setCShadow")

	if len(p.Username)+len(p.Password)+7 > int(buflen) {
		*errnop = C.ERANGE
		return C.NSS_STATUS_TRYAGAIN
	}

	gobuf := C.GoBytes(unsafe.Pointer(buf), C.int(buflen))
	b := bytes.NewBuffer(gobuf)
	b.Reset()

	spwd.sp_namp = (*C.char)(unsafe.Pointer(&gobuf[b.Len()]))
	b.WriteString(p.Username)
	b.WriteByte(0)

	spwd.sp_lstchg = C.long(p.LastChange)
	spwd.sp_min = C.long(p.MinChange)
	spwd.sp_max = C.long(p.MaxChange)
	spwd.sp_warn = C.long(p.PasswordWarn)
	if p.InactiveLockout != nil {
		spwd.sp_inact = C.long(p.InactiveLockout.(int))
	}
	if p.ExpirationDate != nil {
		spwd.sp_expire = C.long(p.ExpirationDate.(int))
	}
	if p.Reserved != nil {
		spwd.sp_flag = C.ulong(p.Reserved.(uint))
	}

	spwd.sp_pwdp = (*C.char)(unsafe.Pointer(&gobuf[b.Len()]))
	b.WriteString(p.Password)
	b.WriteByte(0)

	return C.NSS_STATUS_SUCCESS
}
