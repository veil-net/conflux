package wintun

// The pinned Wintun release, and the digests that make the download safe.
//
// This library is never embedded in conflux, for the two reasons anchor gives for
// never embedding it either: it is GPLv2, so shipping a copy would bring those terms
// with it, and a driver extracted at runtime from a program's own resources is
// exactly the shape of a DLL hijack. It is fetched instead, verified, and placed
// beside the extracted anchord where anchor's loader looks first.
//
// Verify these against https://www.wintun.net before changing them. They are the
// only thing standing between a user and an arbitrary DLL loaded next to a process
// running as LocalSystem.
const (
	Version = "0.14.1"
	ZipURL  = "https://www.wintun.net/builds/wintun-" + Version + ".zip"

	// ZipSHA256 is the digest of the release archive, as published by wintun.net.
	ZipSHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
)

// DLLName is what anchor's loader looks for beside the executable.
const DLLName = "wintun.dll"
