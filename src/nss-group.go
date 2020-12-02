package main

// #include <errno.h>
// #include "nss.h"
// #include <string.h>
// #include <grp.h>
import "C"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"unsafe"
)

//export _nss_http_setgrent
func _nss_http_setgrent(stayopen C.int) C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("_nss_http_setgrent")

	if len(groupEntries) == 0 {
		resp, err := doRequest("group", hostname)
		if err != nil {
			msg := fmt.Sprintf("NSS-HTTP.go: error getting group data: %s\n", err)
			os.Stderr.WriteString(msg)
			return C.NSS_STATUS_UNAVAIL
		}
		if e := json.Unmarshal(resp, &groupEntries); e != nil {
			msg := fmt.Sprintf("NSS-HTTP.go: error unmarshalling group data: %s\n", e)
			os.Stderr.WriteString(msg)
			return C.NSS_STATUS_UNAVAIL
		}
	}

	groupEntryIndex = 0
	return C.NSS_STATUS_SUCCESS
}

//export _nss_http_endgrent
func _nss_http_endgrent() C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("_nss_http_endgrent")

	groupEntries = []group{}
	groupEntryIndex = 0
	return C.NSS_STATUS_SUCCESS
}

//export _nss_http_getgrent_r
func _nss_http_getgrent_r(grp *C.struct_group, buf *C.char, buflen C.size_t, errnop *C.int) C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("_nss_http_getgrent_r")

	if len(groupEntries) == 0 {
		ret := _nss_http_setgrent(0)
		if ret != C.NSS_STATUS_SUCCESS {
			*errnop = C.ENOENT
			return ret
		}
	}

	if groupEntryIndex == len(groupEntries) {
		*errnop = C.ENOENT
		return C.NSS_STATUS_NOTFOUND
	}

	ret := setCGroup(&groupEntries[groupEntryIndex], grp, buf, buflen, errnop)
	if ret != C.NSS_STATUS_SUCCESS {
		return ret
	}

	groupEntryIndex++
	return C.NSS_STATUS_SUCCESS
}

//export _nss_http_getgrnam_r
func _nss_http_getgrnam_r(cname *C.char, grp *C.struct_group, buf *C.char, buflen C.size_t, errnop *C.int) C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("_nss_http_getgrnam_r")

	if len(groupEntries) == 0 {
		ret := _nss_http_setgrent(0)
		if ret != C.NSS_STATUS_SUCCESS {
			*errnop = C.ENOENT
			return ret
		}
	}

	name := C.GoString(cname)
	for _, g := range groupEntries {
		if g.Groupname == name {
			return setCGroup(&g, grp, buf, buflen, errnop)
		}
	}

	*errnop = C.ENOENT
	return C.NSS_STATUS_NOTFOUND
}

//export _nss_http_getgrgid_r
func _nss_http_getgrgid_r(gid uint, grp *C.struct_group, buf *C.char, buflen C.size_t, errnop *C.int) C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("_nss_http_getgrgid_r")

	if len(groupEntries) == 0 {
		ret := _nss_http_setgrent(0)
		if ret != C.NSS_STATUS_SUCCESS {
			*errnop = C.ENOENT
			return ret
		}
	}

	for _, g := range groupEntries {
		if g.GID == gid {
			return setCGroup(&g, grp, buf, buflen, errnop)
		}

	}

	*errnop = C.ENOENT
	return C.NSS_STATUS_NOTFOUND
}

// set C struct values
func setCGroup(p *group, grp *C.struct_group, buf *C.char, buflen C.size_t, errnop *C.int) C.enum_nss_status {
	// If conf.debug -> print func name
	debugFnName("setCGroup")

	if len(p.Groupname)+len(p.Password)+5 > int(buflen) {
		*errnop = C.ERANGE
		return C.NSS_STATUS_TRYAGAIN
	}

	gobuf := C.GoBytes(unsafe.Pointer(buf), C.int(buflen))
	b := bytes.NewBuffer(gobuf)
	b.Reset()

	grp.gr_name = (*C.char)(unsafe.Pointer(&gobuf[b.Len()]))
	b.WriteString(p.Groupname)
	b.WriteByte(0)

	grp.gr_passwd = (*C.char)(unsafe.Pointer(&gobuf[b.Len()]))
	b.WriteString("x")
	b.WriteByte(0)

	grp.gr_gid = C.uint(p.GID)

	cArr := make([]*C.char, len(p.Members)+1)
	for i, name := range p.Members {
		cArr[i] = C.CString(name)
	}

	grp.gr_mem = &cArr[0]

	return C.NSS_STATUS_SUCCESS
}
