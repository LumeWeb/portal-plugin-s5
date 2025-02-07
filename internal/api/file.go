package api

import (
	"context"
	"encoding/hex"
	"errors"
	s5 "go.lumeweb.com/portal-plugin-s5/internal/protocol"
	"go.lumeweb.com/portal/core"
	"io"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	s5libmetadata "go.lumeweb.com/libs5-go/metadata"

	"go.lumeweb.com/libs5-go/encoding"
	"go.lumeweb.com/libs5-go/types"
)

var _ io.ReadSeekCloser = (*S5File)(nil)
var _ fs.File = (*S5File)(nil)
var _ fs.ReadDirFile = (*S5File)(nil)
var _ fs.DirEntry = (*S5File)(nil)
var _ fs.FileInfo = (*S5FileInfo)(nil)

type S5File struct {
	reader   io.ReadCloser
	hash     []byte
	storage  core.StorageService
	metadata core.MetadataService
	record   *core.UploadMetadata
	protocol *s5.S5Protocol
	cid      *encoding.CID
	typ      types.CIDType
	read     bool
	tus      *s5.TusHandler
	ctx      core.Context
	reqCtx   context.Context
	name     string
	root     []byte
	rootType types.CIDType
	rootCid  *encoding.CID
}

func (f *S5File) IsDir() bool {
	return f.typ == types.CIDTypeDirectory
}

func (f *S5File) Type() fs.FileMode {
	if f.typ == types.CIDTypeDirectory {
		return fs.ModeDir
	}

	return 0
}

func (f *S5File) Info() (fs.FileInfo, error) {
	return f.Stat()
}

type FileParams struct {
	Context    core.Context
	ReqContext context.Context
	Hash       []byte
	Type       types.CIDType
	Protocol   *s5.S5Protocol
	Tus        *s5.TusHandler
	Name       string
	Root       []byte
	RootType   types.CIDType
}

func NewFile(params FileParams) *S5File {
	return &S5File{
		ctx:      params.Context,
		reqCtx:   params.ReqContext,
		storage:  params.Context.Service(core.STORAGE_SERVICE).(core.StorageService),
		metadata: params.Context.Service(core.METADATA_SERVICE).(core.MetadataService),
		hash:     params.Hash,
		typ:      params.Type,
		protocol: params.Protocol,
		tus:      params.Tus,
		name:     params.Name,
		root:     params.Root,
		rootType: params.RootType,
	}
}

func (f *S5File) Exists() bool {
	exists, _ := f.tus.UploadHashExists(f.reqCtx, f.hash)

	if exists {
		return true
	}

	_, err := f.metadata.GetUpload(context.Background(), f.hash)

	if err != nil {
		return false
	}

	return true
}

func (f *S5File) Read(p []byte) (n int, err error) {
	err = f.init(0)
	if err != nil {
		return 0, err
	}
	f.read = true

	return f.reader.Read(p)
}

func (f *S5File) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		if !f.read && offset == 0 {
			return 0, nil
		}

		if f.reader != nil {
			err := f.reader.Close()
			if err != nil {
				return 0, err
			}
			f.reader = nil
		}
		err := f.init(offset)
		if err != nil {
			return 0, err
		}
	case io.SeekCurrent:
		return 0, errors.New("not supported")
	case io.SeekEnd:
		return int64(f.Size()), nil
	default:
		return 0, errors.New("invalid whence")
	}

	return 0, nil
}

func (f *S5File) Close() error {
	if f.reader != nil {
		r := f.reader
		f.reader = nil
		return r.Close()
	}

	return nil
}

func (f *S5File) init(offset int64) error {
	if f.reader == nil {
		reader, err := f.tus.GetUploadReader(f.reqCtx, f.hash, offset)

		if err == nil {
			f.reader = reader
			f.read = false
			return nil
		}

		reader, err = f.storage.DownloadObject(context.Background(), f.StorageProtocol(), f.hash, offset)
		if err != nil {
			return err
		}

		f.reader = reader
		f.read = false
	}

	return nil
}

func (f *S5File) Record() (*core.UploadMetadata, error) {
	if f.record == nil {
		exists, tusRecord := f.tus.UploadHashExists(context.Background(), f.hash)

		if exists {
			size, err := f.tus.GetUploadSize(context.Background(), f.hash)
			if err != nil {
				return nil, err
			}
			return &core.UploadMetadata{
				Hash:       f.hash,
				Size:       uint64(size),
				MimeType:   tusRecord.MimeType,
				Created:    tusRecord.CreatedAt,
				Protocol:   f.protocol.Name(),
				UploaderIP: tusRecord.UploaderIP,
				UserID:     tusRecord.UploaderID,
			}, nil
		}

		record, err := f.metadata.GetUpload(context.Background(), f.hash)

		if err != nil {
			return nil, errors.New("file does not exist")
		}

		f.record = &record
	}

	return f.record, nil
}

func (f *S5File) Hash() []byte {
	hashStr := f.HashString()

	if hashStr == "" {
		return nil
	}

	str, err := hex.DecodeString(hashStr)
	if err != nil {
		return nil
	}

	return str
}

func (f *S5File) HashString() string {
	record, err := f.Record()
	if err != nil {
		return ""
	}

	return hex.EncodeToString(record.Hash)
}

func (f *S5File) Name() string {
	if f.name != "" {
		return f.name
	}

	cid, _ := f.CID().ToString()

	return cid
}

func (f *S5File) Modtime() time.Time {
	record, err := f.Record()
	if err != nil {
		return time.Unix(0, 0)
	}

	return record.Created
}
func (f *S5File) Size() uint64 {
	record, err := f.Record()
	if err != nil {
		return 0
	}

	return record.Size
}
func (f *S5File) CID() *encoding.CID {
	if f.cid == nil {
		multihash := encoding.MultihashFromBytes(f.Hash(), types.HashTypeBlake3)

		typ := f.typ
		if typ == 0 {
			typ = types.CIDTypeRaw
		}

		cid := encoding.NewCID(typ, *multihash, f.Size())
		f.cid = cid
	}
	return f.cid
}

func (f *S5File) RootCID() *encoding.CID {
	if f.rootCid == nil {
		if f.root == nil {
			return nil
		}
		multihash := encoding.MultihashFromBytes(f.root, types.HashTypeBlake3)
		typ := f.rootType
		if typ == 0 {
			typ = types.CIDTypeRaw
		}

		cid := encoding.NewCID(typ, *multihash, f.Size())
		f.rootCid = cid

	}

	return f.rootCid
}

func (f *S5File) Mime() string {
	record, err := f.Record()
	if err != nil {
		return ""
	}

	return record.MimeType
}

func (f *S5File) StorageProtocol() core.StorageProtocol {
	return s5.GetStorageProtocol(f.protocol)
}

func (f *S5File) Proof() ([]byte, error) {
	object, err := f.storage.DownloadObjectProof(context.Background(), f.StorageProtocol(), f.hash)

	if err != nil {
		return nil, err
	}

	proof, err := io.ReadAll(object)
	if err != nil {
		return nil, err
	}

	err = object.Close()
	if err != nil {
		return nil, err
	}

	return proof, nil
}
func (f *S5File) Manifest() (s5libmetadata.Metadata, error) {
	cid := f.RootCID()

	if cid == nil {
		cid = f.CID()
	}

	if f.Exists() {
		data, err := io.ReadAll(f)
		if err != nil {
			return nil, err
		}

		_, err = f.Seek(0, io.SeekStart)
		if err != nil {
			return nil, err
		}

		md, err := f.protocol.Node().Services().Storage().ParseMetadata(data, cid)
		if err != nil {
			return nil, err
		}

		return md, nil
	}

	meta, err := f.protocol.Node().Services().Storage().GetMetadataByCID(cid)
	if err != nil {
		return nil, err
	}

	return meta, nil
}

func (f *S5File) Stat() (fs.FileInfo, error) {
	return newS5FileInfo(f), nil
}

type S5FileInfo struct {
	file *S5File
}

func (s S5FileInfo) Name() string {
	return s.file.Name()
}

func (s S5FileInfo) Size() int64 {
	return int64(s.file.Size())
}

func (s S5FileInfo) Mode() fs.FileMode {
	return 0
}

func (s S5FileInfo) ModTime() time.Time {
	return s.file.Modtime()
}

func (s S5FileInfo) IsDir() bool {
	if s.file.name == "." {
		return true
	}

	manifest, err := s.file.Manifest()
	if err == nil && s.file.root != nil {
		webApp, ok := manifest.(*s5libmetadata.WebAppMetadata)
		if ok {
			if slices.Contains(webApp.TryFiles, path.Base(s.file.name)) {
				return true
			}
		}
	}

	return s.file.typ == types.CIDTypeDirectory
}

func (s S5FileInfo) Sys() any {
	return nil
}

func (f *S5File) ReadDir(n int) ([]fs.DirEntry, error) {
	manifest, err := f.Manifest()
	if err != nil {
		return nil, err
	}

	switch f.CID().Type {
	case types.CIDTypeDirectory:
		dir, ok := manifest.(*s5libmetadata.DirectoryMetadata)
		if !ok {
			return nil, errors.New("manifest is not a directory")
		}

		var entries []fs.DirEntry

		for _, file := range dir.Files.Items() {
			entries = append(entries, NewFile(FileParams{
				Context:    f.ctx,
				ReqContext: f.reqCtx,
				Hash:       file.File.CID().Hash.HashBytes(),
				Type:       file.File.CID().Type,
				Tus:        f.tus,
				Name:       file.Name,
			}))
		}

		for _, subDir := range dir.Directories.Items() {
			cid, err := ResolveDirCid(subDir, f.protocol.Node())
			if err != nil {
				return nil, err
			}
			entries = append(entries, NewFile(FileParams{
				Context:    f.ctx,
				ReqContext: f.reqCtx,
				Hash:       cid.Hash.HashBytes(),
				Type:       cid.Type,
				Name:       subDir.Name,
			}))
		}

		return entries, nil

	case types.CIDTypeMetadataWebapp:
		webApp, ok := manifest.(*s5libmetadata.WebAppMetadata)
		if !ok {
			return nil, errors.New("manifest is not a web app")
		}

		var entries []fs.DirEntry
		dirMap := make(map[string]bool)

		webApp.Paths.Keys()

		for _, path := range webApp.Paths.Keys() {
			pathSegments := strings.Split(path, "/")

			// Check if the path is an immediate child (either a file or a direct subdirectory)
			if len(pathSegments) == 1 {
				// It's a file directly within `dirPath`
				entries = append(entries, newWebAppEntry(pathSegments[0], false))
			} else if len(pathSegments) > 1 {
				// It's a subdirectory, but ensure to add each unique subdirectory only once
				subDirName := pathSegments[0] // The immediate subdirectory name
				if _, exists := dirMap[subDirName]; !exists {
					entries = append(entries, newWebAppEntry(subDirName, true))
					dirMap[subDirName] = true
				}
			}
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})

		return entries, nil
	}

	return nil, errors.New("unsupported CID type")
}

func newS5FileInfo(file *S5File) *S5FileInfo {
	return &S5FileInfo{
		file: file,
	}
}

type webAppEntry struct {
	name  string
	isDir bool
}

func newWebAppEntry(name string, isDir bool) *webAppEntry {
	return &webAppEntry{name: name, isDir: isDir}
}

func (d *webAppEntry) Name() string {
	return d.name
}

func (d *webAppEntry) IsDir() bool {
	return d.isDir
}

func (d *webAppEntry) Type() fs.FileMode {
	if d.isDir {
		return fs.ModeDir
	}

	return 0
}

func (d *webAppEntry) Info() (fs.FileInfo, error) {
	return &webAppFileInfo{name: d.name, isDir: true}, nil
}

type webAppFileInfo struct {
	name  string
	isDir bool
}

func (fi *webAppFileInfo) Name() string { return fi.name }
func (fi *webAppFileInfo) Size() int64  { return 0 }
func (fi *webAppFileInfo) Mode() fs.FileMode {
	if fi.isDir {
		return fs.ModeDir
	}

	return 0
}
func (fi *webAppFileInfo) ModTime() time.Time {
	return time.Time{}
}
func (fi *webAppFileInfo) IsDir() bool {
	return fi.isDir
}
func (fi *webAppFileInfo) Sys() interface{} {
	return nil
}
