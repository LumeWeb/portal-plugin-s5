package api

import (
	"context"
	"errors"
	"io/fs"
	"path"

	"go.lumeweb.com/libs5-go/encoding"
	"go.lumeweb.com/libs5-go/metadata"
)

var _ fs.FS = (*webAppFs)(nil)

type webAppFs struct {
	root   *encoding.CID
	s5     *S5API
	reqCtx context.Context
}

func (w webAppFs) Open(name string) (fs.File, error) {
	file := w.s5.newFile(w.reqCtx, FileParams{
		Hash: w.root.Hash.HashBytes(),
		Type: w.root.Type,
	})

	manifest, err := file.Manifest()
	if err != nil {
		return nil, err
	}

	webApp, ok := manifest.(*metadata.WebAppMetadata)

	if !ok {
		return nil, errors.New("manifest is not a web app")
	}

	if name == "." {
		return w.s5.newFile(w.reqCtx, FileParams{
			Hash: w.root.Hash.HashBytes(),
			Type: w.root.Type,
			Name: name,
		}), nil
	}

	item, ok := webApp.Paths.Get(name)

	if !ok {
		name = path.Join(name, "index.html")
		item, ok = webApp.Paths.Get(name)
		if !ok {
			return nil, fs.ErrNotExist
		}

		return w.s5.newFile(w.reqCtx, FileParams{
			Hash:     item.Cid.Hash.HashBytes(),
			Type:     item.Cid.Type,
			Name:     name,
			Root:     w.root.Hash.HashBytes(),
			RootType: w.root.Type,
		}), nil
	}
	return w.s5.newFile(w.reqCtx, FileParams{
		Hash: item.Cid.Hash.HashBytes(),
		Type: item.Cid.Type,
		Name: name,
	}), nil
}

func newWebAppFs(root *encoding.CID, s5 *S5API, reqCtx context.Context) *webAppFs {
	return &webAppFs{
		root: root,
		s5:   s5,
	}
}
