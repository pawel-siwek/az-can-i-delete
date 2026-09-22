package storage

import "strings"

// Class is what an operation against a storage account means. The verdict
// rules count transactions by class, so the table below is where "is anybody
// using this account?" is actually decided.
type Class string

// The operation classes of SPEC appendix L section 7.
const (
	Read      Class = "READ"
	Write     Class = "WRITE"
	Delete    Class = "DELETE"
	Enumerate Class = "ENUMERATE"
	Metadata  Class = "METADATA"
	Lease     Class = "LEASE"
	Polling   Class = "POLLING"
	Session   Class = "SESSION"
	Other     Class = "OTHER"
)

// writePrimeExcluded are the writes the amended rules keep out of WRITE′: they
// are metadata maintenance and lifecycle work rather than somebody writing
// data. They still count as activity for the silence rule.
var writePrimeExcluded = map[string]bool{
	"setblobtier": true, "setblobtags": true, "setblobmetadata": true,
	"setblobexpiry": true, "deleteblob": true, "abortcopyblob": true,
}

// classes is the operation table. Names are compared case-insensitively; an
// operation that is not here is OTHER, which the silence rule refuses to treat
// as inactivity.
var classes = map[string]Class{}

func init() {
	register(Read,
		// blob
		"GetBlob", "QueryBlobContents", "GetBlockList", "GetPageRanges", "GetBlobTags",
		"FindBlobsByTags", "GetBlobMetadata", "GetBlobLeaseInfo",
		// data lake
		"ReadFile", "GetPathStatus", "GetFileProperties", "GetPathAccessControl",
		// file REST
		"GetFile", "ListFileRanges", "GetFileMetadata", "GetFileCopyInformation", "GetFilePermission",
		// SMB
		"Read",
		// queue: a message read for processing is a real read, not a poll
		"GetMessageWrite",
		// table
		"QueryEntity", "QueryEntities")
	register(Write,
		"PutBlob", "PutBlock", "PutBlockFromURL", "PutBlockList", "AppendBlock", "PutPage",
		"ClearPage", "CopyBlob", "CopyBlobSource", "CopyBlobDestination", "IncrementalCopyBlob",
		"SnapshotBlob", "UndeleteBlob", "SetBlobProperties",
		"SetBlobMetadata", "SetBlobExpiry", "SetBlobTags", "SetBlobTier", "AbortCopyBlob",
		"CreatePathFile", "CreatePathDir", "AppendFile", "FlushFile", "RenamePathFile",
		"RenamePathDir", "SetFileProperties", "SetPathAccessControl",
		"CreateFile", "PutRange", "PutRangeFromURL", "ClearRange", "CopyFile", "CopyFileSource",
		"CopyFileDestination", "AbortCopyFile", "CreateDirectory", "SetFileMetadata",
		"SetDirectoryMetadata", "PutFilePermission", "CreateFileSnapshot",
		"Write", "SetInfo", "Flush", "Lock", "Ioctl", "OplockBreak",
		"PutMessage", "UpdateMessage",
		"InsertEntity", "InsertOrMergeEntity", "InsertOrReplaceEntity", "MergeEntity",
		"UpdateEntity", "EntityGroupTransaction")
	register(Delete,
		"DeleteBlob", "DeleteFile", "DeleteDirectory", "DeleteMessage", "ClearMessages", "DeleteEntity")
	register(Enumerate,
		"ListContainers", "ListBlobs", "ListFilesystems", "ListFilesystemDir", "ListFilesystemFile",
		"ListShares", "ListFiles", "ListFileSnapshots", "ListHandles", "QueryDirectory",
		"ListQueues", "QueryTables", "QueryTable")
	register(Metadata,
		"GetBlobProperties", "CreateContainer", "DeleteContainer", "GetContainerProperties",
		"GetContainerMetadata", "GetContainerACL", "SetContainerACL", "SetContainerMetadata",
		"GetAccountInformation", "GetBlobServiceProperties", "SetBlobServiceProperties",
		"GetBlobServiceStats", "GetUserDelegationKey", "BlobPreflightRequest",
		"CreateFilesystem", "DeleteFilesystem", "GetFilesystemProperties", "SetFilesystemProperties",
		"CreateShare", "DeleteShare", "GetShareProperties", "GetShareMetadata", "GetShareAcl",
		"GetShareStats", "SetShareAcl", "SetShareMetadata", "SetShareProperties", "SnapshotShare",
		"GetFileServiceProperties", "SetFileServiceProperties", "FilePreflightRequest",
		"FileSessionConnect", "GetEncryptionKey", "GetFileShareUniqueId", "GetPostMigrationFileInfo",
		"GetDirectoryMetadata", "GetDirectoryProperties",
		"QueryInfo", "ChangeNotify", "Create",
		"CreateQueue", "DeleteQueue", "GetQueue", "GetQueueMetadata", "SetQueueMetadata",
		"GetQueueServiceProperties", "SetQueueServiceProperties", "QueuePreflightRequest",
		"CreateTable", "DeleteTable", "GetTableServiceProperties", "SetTableServiceProperties",
		"TablePreflightRequest")
	register(Lease,
		"AcquireBlobLease", "RenewBlobLease", "ChangeBlobLease", "ReleaseBlobLease", "BreakBlobLease",
		"AcquireContainerLease", "RenewContainerLease", "ChangeContainerLease",
		"ReleaseContainerLease", "BreakContainerLease", "LeaseFile",
		"AcquireFileLease", "BreakFileLease", "ChangeFileLease", "ReleaseFileLease")
	register(Session,
		"Negotiate", "SessionSetup", "TreeConnect", "TreeDisconnect", "Logoff", "Echo", "Cancel", "Close")
	register(Polling, "GetMessage", "GetMessages", "GetMessageRead", "PeekMessage", "PeekMessages")
}

func register(class Class, names ...string) {
	for _, name := range names {
		classes[strings.ToLower(name)] = class
	}
}

// Classify returns an operation's class. An unrecognized name is OTHER, which
// the rules treat as activity that could not be understood rather than as
// silence — that is what keeps an unclassified protocol such as NFS from
// reading as an idle account.
func Classify(apiName string) Class {
	if class, ok := classes[strings.ToLower(strings.TrimSpace(apiName))]; ok {
		return class
	}
	if apiName == "" {
		return Other
	}
	return Other
}

// WritePrime reports whether an operation counts towards the amended write
// rule. Metadata maintenance and lifecycle deletes do not.
func WritePrime(apiName string) bool {
	switch Classify(apiName) {
	case Write, Delete:
		return !writePrimeExcluded[strings.ToLower(apiName)]
	default:
		return false
	}
}

// Activity reports whether an operation is user activity for the silence rule:
// reads, writes, deletes, leases and queue polling all count.
func Activity(class Class) bool {
	switch class {
	case Read, Write, Delete, Lease, Polling:
		return true
	default:
		return false
	}
}

// SMBSession reports the operations that mean a client has a share mounted.
func SMBSession(apiName string) bool {
	switch strings.ToLower(apiName) {
	case "sessionsetup", "treeconnect":
		return true
	default:
		return false
	}
}
