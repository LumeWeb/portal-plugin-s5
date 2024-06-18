package protocol

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	s5config "go.lumeweb.com/libs5-go/config"
	s5db "go.lumeweb.com/libs5-go/db"
	s5ed "go.lumeweb.com/libs5-go/ed25519"
	"go.lumeweb.com/libs5-go/encoding"
	s5node "go.lumeweb.com/libs5-go/node"
	s5service "go.lumeweb.com/libs5-go/service"
	s5services "go.lumeweb.com/libs5-go/service/default"
	s5storage "go.lumeweb.com/libs5-go/storage"
	"go.lumeweb.com/libs5-go/types"
	"go.lumeweb.com/portal/config"
	"go.lumeweb.com/portal/core"
	"go.uber.org/zap"
	"golang.org/x/crypto/hkdf"
	"io"
	"time"
)

const ETCD_DB_PREFIX = "s5-db"

var (
	_ s5storage.ProviderStore = (*S5ProviderStore)(nil)
	_ core.Protocol           = (*S5Protocol)(nil)
	_ core.ProtocolInit       = (*S5Protocol)(nil)
	_ core.ProtocolStart      = (*S5Protocol)(nil)
	_ core.ProtocolStop       = (*S5Protocol)(nil)
	_ core.SyncProtocol       = (*S5Protocol)(nil)
	_ core.StorageProtocol    = (*S5Protocol)(nil)
)

type S5Protocol struct {
	portalConfig config.Manager
	config       *Config
	logger       *core.Logger
	storage      core.StorageService
	node         *s5node.Node
	tusHandler   *TusHandler
	store        *S5ProviderStore
}

func (s *S5Protocol) TusHandler() *TusHandler {
	return s.tusHandler
}

func NewS5Protocol() (*S5Protocol, []core.ContextBuilderOption, error) {

	handler, handlerOpts := NewTusHandler()

	proto := &S5Protocol{
		tusHandler: handler,
	}

	cfg, err := configureS5Protocol(proto)

	if err != nil {
		return nil, nil, err
	}

	opts := core.ContextOptions(
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			proto.portalConfig = ctx.Config()
			proto.logger = ctx.Logger()
			proto.storage = ctx.Service(core.STORAGE_SERVICE).(core.StorageService)
			return nil
		}),
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			params := s5service.ServiceParams{
				Logger: proto.logger.Logger,
				Config: cfg,
				Db:     cfg.DB,
			}

			node := s5node.NewNode(cfg, s5node.NewServices(
				s5node.ServicesParams{
					P2P:      s5services.NewP2P(params),
					Registry: s5services.NewRegistry(params),
					HTTP:     s5services.NewHTTP(params),
					Storage:  s5services.NewStorage(params),
				},
			))

			proto.store = NewS5ProviderStore(ctx, proto.tusHandler)
			proto.node = node

			return nil
		}),
	)

	opts = append(opts, handlerOpts...)

	return proto, opts, nil
}

func configureS5Protocol(proto *S5Protocol) (*s5config.NodeConfig, error) {
	cfg := proto.Config().(*Config)
	cm := proto.portalConfig
	portalCfg := cm.Config()

	err := cm.ConfigureProtocol(proto.Name(), cfg)
	if err != nil {
		return nil, err
	}

	cfg.HTTP.API.Domain = fmt.Sprintf("s5.%s", portalCfg.Core.Domain)

	if portalCfg.Core.ExternalPort != 0 {
		cfg.HTTP.API.Port = portalCfg.Core.ExternalPort
	} else {
		cfg.HTTP.API.Port = portalCfg.Core.Port
	}

	hasher := hkdf.New(sha256.New, portalCfg.Core.Identity.PrivateKey(), nil, []byte("s5"))
	derivedSeed := make([]byte, 32)

	if _, err := io.ReadFull(hasher, derivedSeed); err != nil {
		proto.logger.Fatal("Failed to generate child key seed", zap.Error(err))
		return nil, err
	}

	p := ed25519.NewKeyFromSeed(derivedSeed)
	cfg.KeyPair = s5ed.New(p)

	cfg.DB, err = getDb(cm, proto.logger)
	if err != nil {
		return nil, err
	}

	cfg.Logger = proto.logger.Named("s5")

	return cfg.NodeConfig, nil
}

func (s *S5Protocol) Config() config.ProtocolConfig {
	if s.config == nil {
		s.config = &Config{
			NodeConfig: &s5config.NodeConfig{},
		}
	}

	return s.config
}
func NewS5ProviderStore(ctx core.Context, tus *TusHandler) *S5ProviderStore {
	return &S5ProviderStore{
		ctx:      ctx,
		config:   ctx.Config(),
		logger:   ctx.Logger(),
		tus:      tus,
		metadata: ctx.Service(core.METADATA_SERVICE).(core.MetadataService),
	}
}

func (s *S5Protocol) Init(ctx *core.Context) error {
	s.node.Services().Storage().SetProviderStore(s.store)

	err := s.node.Init(*ctx)
	if err != nil {
		return err
	}

	s.tusHandler.SetStorageProtocol(GetStorageProtocol(s))

	err = s.tusHandler.Init()
	if err != nil {
		return err
	}

	return nil
}
func (s *S5Protocol) Start(ctx core.Context) error {
	err := s.node.Start(ctx)
	if err != nil {
		return err
	}

	identity, err := s.node.NodeId().ToString()

	if err != nil {
		return err
	}

	s.logger.Info("S5 protocol started", zap.String("identity", identity), zap.String("network", s.node.NetworkId()), zap.String("domain", s.node.Config().HTTP.API.Domain))

	return nil
}

func (s *S5Protocol) Stop(ctx core.Context) error {
	err := s.node.Stop(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *S5Protocol) Name() string {
	return "s5"
}

func (s *S5Protocol) Node() *s5node.Node {
	return s.node
}

func (s *S5Protocol) EncodeFileName(bytes []byte) string {
	bytes = append([]byte{byte(types.HashTypeBlake3)}, bytes...)

	hash, err := encoding.NewMultihash(bytes).ToBase64Url()
	if err != nil {
		s.logger.Error("error encoding hash", zap.Error(err))
		panic(err)
	}

	return hash
}

func (s *S5Protocol) ValidIdentifier(identifier string) bool {
	ret, err := hex.DecodeString(identifier)
	if err == nil && len(ret) == 32 {
		return true
	}

	ret, err = base64.RawURLEncoding.DecodeString(identifier)

	if err == nil && len(ret) == 33 {
		hash, err := encoding.MultihashFromBase64Url(identifier)

		if err == nil {
			return hash.FunctionType() == types.HashTypeBlake3
		}
	}

	cid, err := encoding.CIDFromString(identifier)

	if err == nil {
		return cid.Hash.FunctionType() == types.HashTypeBlake3
	}

	ret, err = base64.RawURLEncoding.DecodeString(identifier)

	if err == nil && len(ret) == 32 {
		return true
	}

	return false
}

func (s *S5Protocol) HashFromIdentifier(identifier string) ([]byte, error) {
	ret, err := hex.DecodeString(identifier)
	if err == nil && len(ret) == 32 {
		return ret, nil
	}

	ret, err = base64.RawURLEncoding.DecodeString(identifier)
	if err == nil && len(ret) == 32 {
		return ret, nil
	}

	hash, err := encoding.MultihashFromBase64Url(identifier)
	if err == nil {
		return hash.HashBytes(), nil
	}

	cid, err := encoding.CIDFromString(identifier)
	if err == nil {
		return cid.Hash.HashBytes(), nil
	}

	return nil, fmt.Errorf("invalid identifier")
}

func (s *S5Protocol) StorageProtocol() core.StorageProtocol {
	return s
}

type S5ProviderStore struct {
	ctx      core.Context
	config   config.Manager
	logger   *core.Logger
	tus      *TusHandler
	metadata core.MetadataService
}

func (s S5ProviderStore) CanProvide(hash *encoding.Multihash, kind []types.StorageLocationType) bool {
	ctx := context.Background()
	for _, t := range kind {
		switch t {
		case types.StorageLocationTypeArchive, types.StorageLocationTypeFile, types.StorageLocationTypeFull:
			rawHash := hash.HashBytes()

			if exists, upload := s.tus.UploadHashExists(ctx, rawHash); exists {
				if upload.Completed {
					return true
				}

			}
			if _, err := s.metadata.GetUpload(ctx, rawHash); err == nil {
				return true
			}
		}
	}
	return false
}

func (s S5ProviderStore) Provide(hash *encoding.Multihash, kind []types.StorageLocationType) (s5storage.StorageLocation, error) {
	for _, t := range kind {
		if !s.CanProvide(hash, []types.StorageLocationType{t}) {
			continue
		}

		switch t {
		case types.StorageLocationTypeArchive:
			return s5storage.NewStorageLocation(int(types.StorageLocationTypeArchive), []string{}, calculateExpiry(24*time.Hour)), nil
		case types.StorageLocationTypeFile, types.StorageLocationTypeFull:
			return s5storage.NewStorageLocation(int(types.StorageLocationTypeFull), []string{generateDownloadUrl(hash, s.ctx), generateProofUrl(hash, s.ctx)}, calculateExpiry(1*time.Hour)), nil
		}
	}

	hashStr, err := hash.ToString()
	if err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("could not provide hash %s for types %v", hashStr, kind)
}

func calculateExpiry(duration time.Duration) int64 {
	return time.Now().Add(duration).Unix()
}

func generateDownloadUrl(hash *encoding.Multihash, ctx core.Context) string {
	cfg := ctx.Config()
	logger := ctx.Logger()
	domain := cfg.Config().Core.Domain

	hashStr, err := hash.ToBase64Url()
	if err != nil {
		logger.Error("error encoding hash", zap.Error(err))
	}

	return fmt.Sprintf("https://s5.%s/s5/download/%s", domain, hashStr)
}

func generateProofUrl(hash *encoding.Multihash, ctx core.Context) string {
	cfg := ctx.Config()
	logger := ctx.Logger()
	domain := cfg.Config().Core.Domain

	hashStr, err := hash.ToBase64Url()
	if err != nil {
		logger.Error("error encoding hash", zap.Error(err))
	}

	return fmt.Sprintf("https://s5.%s/s5/download/%s.obao", domain, hashStr)
}

func GetStorageProtocol(obj any) core.StorageProtocol {
	if protocol, ok := obj.(*S5Protocol); ok {
		return protocol.StorageProtocol()
	}

	panic("invalid protocol")
}

func getDbMode(cm config.Manager) string {
	cfg := cm.Config().Protocol["s5"].(*Config)

	switch cfg.Db.Type {
	case "db":
		return "db"
	case "etcd":
		if cm.Config().Core.Clustered.Enabled {
			return "etcd"
		}

		return "db"
	}

	return "db"
}

func getDbCacheMode(cm config.Manager) string {
	cfg := cm.Config().Protocol["s5"].(*Config)

	switch cfg.Db.Cache.Type {
	case "lru":
		return "lru"
	}

	return "none"
}

func getDbCache(cm config.Manager) (s5db.Cache, error) {
	cfg := cm.Config().Protocol["s5"].(*Config)

	switch cfg.Db.Cache.Type {
	case "lru":
		return s5db.NewLRUCache(cfg.Db.Cache.LRUCacheSize)
	}

	return nil, nil
}

func getDb(cm config.Manager, logger *core.Logger) (s5db.KVStore, error) {
	mode := getLockerMode(cm, logger)
	cache, err := getDbCache(cm)

	if err != nil {
		return nil, err
	}

	switch mode {
	case "db":
		cfg := cm.Config().Protocol["s5"].(*Config)
		return s5db.NewBboltDBKVStore(cfg.Db.DbPath, cache), nil
	case "etcd":
		client, err := cm.Config().Core.Clustered.Etcd.Client()
		if err != nil {
			return nil, err
		}

		kvStore := s5db.NewEtcdKVStore(client, ETCD_DB_PREFIX, cache, 0)

		return kvStore, nil
	}

	return nil, nil
}
