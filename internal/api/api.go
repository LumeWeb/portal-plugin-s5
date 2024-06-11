package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/LumeWeb/httputil"
	"github.com/LumeWeb/libs5-go/encoding"
	s5libmetadata "github.com/LumeWeb/libs5-go/metadata"
	"github.com/LumeWeb/libs5-go/protocol"
	"github.com/LumeWeb/libs5-go/service"
	s5storage "github.com/LumeWeb/libs5-go/storage"
	"github.com/LumeWeb/libs5-go/storage/provider"
	"github.com/LumeWeb/libs5-go/types"
	"github.com/LumeWeb/portal-plugin-s5/internal/cron/define"
	"github.com/LumeWeb/portal-plugin-s5/internal/db"
	s5 "github.com/LumeWeb/portal-plugin-s5/internal/protocol"
	"github.com/LumeWeb/portal/bao"
	"github.com/LumeWeb/portal/config"
	"github.com/LumeWeb/portal/core"
	"github.com/LumeWeb/portal/db/models"
	"github.com/LumeWeb/portal/middleware"
	"github.com/LumeWeb/portal/middleware/swagger"
	"github.com/ddo/rq"
	"github.com/gorilla/mux"
	"github.com/vmihailenco/msgpack/v5"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/LumeWeb/libs5-go/node"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/dnslink-std/go"
	"github.com/gabriel-vasile/mimetype"
	muxHandlers "github.com/gorilla/handlers"
	"github.com/rs/cors"
	"github.com/samber/lo"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"nhooyr.io/websocket"
)

var (
	_ core.API         = (*S5API)(nil)
	_ core.RoutableAPI = (*S5API)(nil)
	_ core.APIInit     = (*S5API)(nil)
)

const protocolName = "s5"

//go:embed swagger.yaml
var swagSpec []byte

type S5API struct {
	ctx        core.Context
	config     config.Manager
	user       core.UserService
	auth       core.AuthService
	pin        core.PinService
	storage    core.StorageService
	metadata   core.MetadataService
	db         *gorm.DB
	logger     *core.Logger
	cron       core.CronService
	_import    core.ImportService
	sync       core.SyncService
	dnslink    core.DNSLinkService
	protocol   *s5.S5Protocol
	tusHandler *s5.TusHandler
}

func NewS5API(ctx core.Context) *S5API {
	return &S5API{
		ctx:      ctx,
		config:   ctx.Config(),
		user:     ctx.Services().User(),
		auth:     ctx.Services().Auth(),
		pin:      ctx.Services().Pin(),
		storage:  ctx.Services().Storage(),
		metadata: ctx.Services().Metadata(),
		db:       ctx.DB(),
		logger:   ctx.Logger(),
		cron:     ctx.Services().Cron(),
		_import:  ctx.Services().Importer(),
		sync:     ctx.Services().Sync(),
		dnslink:  ctx.Services().DNSLink(),
	}
}

func (s S5API) Subdomain() string {
	return "s5"
}

func (s *S5API) Init(_ *core.Context) error {
	proto, err := core.GetProtocol(protocolName)
	if err != nil {
		return err
	}

	s.protocol = proto.(*s5.S5Protocol)
	s.tusHandler = proto.(*s5.S5Protocol).TusHandler()
	return nil
}

func (s *S5API) Can(_ http.ResponseWriter, r *http.Request) bool {
	host := r.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	resolve, err := dnslink.Resolve(host)
	if err != nil {
		return false
	}

	if _, ok := resolve.Links[protocolName]; !ok {
		return false
	}

	decodedCid, err := encoding.CIDFromString(resolve.Links[protocolName][0].Identifier)

	if err != nil {
		s.logger.Error("Error decoding CID", zap.Error(err))
		return false
	}

	hash := decodedCid.Hash.HashBytes()

	upload, err := s.metadata.GetUpload(r.Context(), hash)
	if err != nil {
		return false
	}

	if upload.Protocol != protocolName {
		return false
	}

	exists, _, err := s.dnslink.DNSLinkExists(hash)
	if err != nil {
		return false
	}

	if !exists {
		return false
	}

	ctx := context.WithValue(r.Context(), "cid", decodedCid)

	*r = *r.WithContext(ctx)

	return true
}

func (s *S5API) Handle(w http.ResponseWriter, r *http.Request) {
	cidVal := r.Context().Value("cid")

	if cidVal == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	cid := cidVal.(*encoding.CID)

	if cid.Type == types.CIDTypeResolver {
		entry, err := s.getNode().Services().Registry().Get(cid.Hash.FullBytes())
		if err != nil {
			s.logger.Error("Error getting registry entry", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		cid, err = encoding.CIDFromRegistry(entry.Data())
		if err != nil {
			s.logger.Error("Error getting CID from registry entry", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	switch cid.Type {
	case types.CIDTypeRaw:
		s.handleDnsLinkRaw(w, r, cid)
	case types.CIDTypeMetadataWebapp:
		s.handleDnsLinkWebapp(w, r, cid)
	case types.CIDTypeDirectory:
		s.handleDnsLinkDirectory(w, r, cid)
	default:
		w.WriteHeader(http.StatusUnsupportedMediaType)
	}
}

func (s *S5API) handleDnsLinkRaw(w http.ResponseWriter, r *http.Request, cid *encoding.CID) {
	file := s.newFile(r.Context(), FileParams{
		Hash: cid.Hash.HashBytes(),
		Type: cid.Type,
	})

	if !file.Exists() {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	defer func(file io.ReadCloser) {
		err := file.Close()
		if err != nil {
			s.logger.Error("error closing file", zap.Error(err))
		}
	}(file)

	w.Header().Set("Content-Type", file.Mime())

	http.ServeContent(w, r, file.Name(), file.Modtime(), file)
}

func (s *S5API) handleDnsLinkWebapp(w http.ResponseWriter, r *http.Request, cid *encoding.CID) {
	http.FileServer(http.FS(newWebAppFs(cid, s, r.Context()))).ServeHTTP(w, r)
}

func (s *S5API) handleDnsLinkDirectory(w http.ResponseWriter, r *http.Request, cid *encoding.CID) {
	http.FileServer(http.FS(newDirFs(cid, s, r.Context()))).ServeHTTP(w, r)
}

type s5TusJwtResponseWriter struct {
	http.ResponseWriter
	req *http.Request
}

func (w *s5TusJwtResponseWriter) WriteHeader(statusCode int) {
	// Check if this is the specific route and status
	if statusCode == http.StatusCreated {
		location := w.Header().Get("Location")
		authToken := middleware.ParseAuthTokenHeader(w.req.Header)

		if authToken != "" && location != "" {

			parsedUrl, _ := url.Parse(location)

			query := parsedUrl.Query()
			query.Set("auth_token", authToken)
			parsedUrl.RawQuery = query.Encode()

			w.Header().Set("Location", parsedUrl.String())
		}
	}

	w.ResponseWriter.WriteHeader(statusCode)
}

func tusMiddleware(tusHandler *s5.TusHandler) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), "protocol", "s5")
			r = r.WithContext(ctx)

			// Strip prefix
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/s5/upload/tus")

			// Inject JWT
			res := w
			if r.Method == http.MethodPost && r.URL.Path == "" {
				res = &s5TusJwtResponseWriter{ResponseWriter: w, req: r}
			}

			// Serve the Tus handler
			tusHandler.Tus().ServeHTTP(res, r)
		})
	}
}

type readSeekNopCloser struct {
	*bytes.Reader
}

func (rsnc readSeekNopCloser) Close() error {
	return nil
}

func (s *S5API) smallFileUpload(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user := middleware.GetUserFromContext(r.Context())

	file, size, err := s.prepareFileUpload(r)
	if err != nil {
		_ = ctx.Error(err, http.StatusBadRequest)
		return
	}
	defer func(file io.ReadSeekCloser) {
		err := file.Close()
		if err != nil {
			s.logger.Error("Error closing file", zap.Error(err))
		}
	}(file)

	newUpload, err := s.storage.UploadObject(r.Context(), s5.GetStorageProtocol(s.protocol), file, size, nil, nil)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyFileUploadFailed, err), http.StatusInternalServerError)
		return
	}

	newUpload.UserID = user
	newUpload.UploaderIP = r.RemoteAddr

	err = s.metadata.SaveUpload(r.Context(), *newUpload, true)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyFileUploadFailed, err), http.StatusInternalServerError)
		return
	}

	cid, err := encoding.CIDFromHash(newUpload.Hash, newUpload.Size, types.CIDTypeRaw, types.HashTypeBlake3)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyFileUploadFailed, err), http.StatusInternalServerError)
		return
	}

	err = s.pin.PinByHash(newUpload.Hash, user)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyFileUploadFailed, err), http.StatusInternalServerError)
		return
	}

	cidStr, err := cid.ToString()
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyFileUploadFailed, err), http.StatusInternalServerError)
		return
	}

	err = s.sync.Update(*newUpload)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyFileUploadFailed, err), http.StatusInternalServerError)
		return
	}

	response := &SmallUploadResponse{
		CID: cidStr,
	}
	ctx.Encode(response)
}

func (s *S5API) prepareFileUpload(r *http.Request) (file io.ReadSeekCloser, size uint64, s5Err error) {
	contentType := r.Header.Get("Content-Type")

	// Handle multipart form data uploads
	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(int64(s.config.Config().Core.PostUploadLimit)); err != nil {
			return nil, size, NewS5Error(ErrKeyFileUploadFailed, err)
		}

		multipartFile, multipartHeader, err := r.FormFile("file")
		if err != nil {
			return nil, size, NewS5Error(ErrKeyFileUploadFailed, err)
		}

		size = uint64(multipartHeader.Size)

		return multipartFile, size, nil
	}

	// Handle raw body uploads
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, size, NewS5Error(ErrKeyFileUploadFailed, err)
	}

	buffer := readSeekNopCloser{bytes.NewReader(data)}

	size = uint64(len(data))

	return buffer, size, nil
}

func (s *S5API) accountRegisterChallenge(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var pubkey string
	err := ctx.DecodeForm("pubKey", &pubkey)
	if err != nil {
		return
	}

	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
		return
	}

	decodedKey, err := base64.RawURLEncoding.DecodeString(pubkey)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidFileFormat, err), http.StatusBadRequest)
		return
	}

	if len(decodedKey) != 33 || int(decodedKey[0]) != int(types.HashTypeEd25519) {
		_ = ctx.Error(NewS5Error(ErrKeyDataIntegrityError, fmt.Errorf("invalid public key format")), http.StatusBadRequest)
		return
	}

	result := s.db.Create(&db.S5Challenge{
		Pubkey:    pubkey,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Type:      "register",
	})

	if result.Error != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, result.Error), http.StatusInternalServerError)
		return
	}

	response := &AccountRegisterChallengeResponse{
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
	}
	ctx.Encode(response)
}

func (s *S5API) accountRegister(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var request AccountRegisterRequest
	err := ctx.Decode(&request)
	if err != nil {
		return
	}

	decodedKey, err := base64.RawURLEncoding.DecodeString(request.Pubkey)
	if err != nil || len(decodedKey) != 33 || int(decodedKey[0]) != int(types.HashTypeEd25519) {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidFileFormat, err), http.StatusBadRequest)
		return
	}

	challenge := db.S5Challenge{
		Pubkey: request.Pubkey,
		Type:   "register",
	}

	if result := s.db.Where(&challenge).First(&challenge); result.RowsAffected == 0 || result.Error != nil {
		_ = ctx.Error(NewS5Error(ErrKeyResourceNotFound, result.Error), http.StatusNotFound)
		return
	}

	decodedResponse, err := base64.RawURLEncoding.DecodeString(request.Response)
	if err != nil || len(decodedResponse) != 65 {
		_ = ctx.Error(NewS5Error(ErrKeyDataIntegrityError, err), http.StatusBadRequest)
		return
	}

	decodedChallenge, err := base64.RawURLEncoding.DecodeString(challenge.Challenge)
	if err != nil || !bytes.Equal(decodedResponse[1:33], decodedChallenge) {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidOperation, err), http.StatusBadRequest)
		return
	}

	decodedSignature, err := base64.RawURLEncoding.DecodeString(request.Signature)
	if err != nil || !ed25519.Verify(decodedKey[1:], decodedResponse, decodedSignature) {
		_ = ctx.Error(NewS5Error(ErrKeyAuthorizationFailed, err), http.StatusUnauthorized)
		return
	}

	if request.Email == "" {
		request.Email = fmt.Sprintf("%s@%s", hex.EncodeToString(decodedKey[1:]), "example.com")
	}

	if accountExists, _, _ := s.user.EmailExists(request.Email); accountExists {
		_ = ctx.Error(NewS5Error(ErrKeyResourceLimitExceeded, fmt.Errorf("email already exists")), http.StatusConflict)
		return
	}

	if pubkeyExists, _, _ := s.user.PubkeyExists(hex.EncodeToString(decodedKey[1:])); pubkeyExists {
		_ = ctx.Error(NewS5Error(ErrKeyResourceLimitExceeded, fmt.Errorf("pubkey already exists")), http.StatusConflict)
		return
	}

	passwd := make([]byte, 32)
	if _, err = rand.Read(passwd); err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
		return
	}

	newAccount, err := s.user.CreateAccount(request.Email, string(passwd), false)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err), http.StatusInternalServerError)
		return
	}

	rawPubkey := hex.EncodeToString(decodedKey[1:])
	if err = s.user.AddPubkeyToAccount(*newAccount, rawPubkey); err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err), http.StatusInternalServerError)
		return
	}

	jwt, err := s.auth.LoginPubkey(rawPubkey, r.RemoteAddr)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyAuthenticationFailed, err), http.StatusUnauthorized)
		return
	}

	if result := s.db.Delete(&challenge); result.Error != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, result.Error), http.StatusInternalServerError)
		return
	}

	core.SetAuthCookie(w, s.ctx, jwt)
}

func (s *S5API) accountLoginChallenge(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var pubkey string
	err := ctx.DecodeForm("pubKey", &pubkey)
	if err != nil {
		return
	}

	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
		return
	}

	decodedKey, err := base64.RawURLEncoding.DecodeString(pubkey)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidFileFormat, err), http.StatusBadRequest)
		return
	}

	if len(decodedKey) != 33 || int(decodedKey[0]) != int(types.HashTypeEd25519) {
		_ = ctx.Error(NewS5Error(ErrKeyUnsupportedFileType, fmt.Errorf("public key not supported")), http.StatusBadRequest)
		return
	}

	pubkeyExists, _, _ := s.user.PubkeyExists(hex.EncodeToString(decodedKey[1:]))
	if !pubkeyExists {
		_ = ctx.Error(NewS5Error(ErrKeyResourceNotFound, fmt.Errorf("public key does not exist")), http.StatusNotFound)
		return
	}

	result := s.db.Create(&db.S5Challenge{
		Pubkey:    pubkey,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Type:      "login",
	})

	if result.Error != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, result.Error), http.StatusInternalServerError)
		return
	}

	response := &AccountLoginChallengeResponse{
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
	}
	ctx.Encode(response)
}

func (s *S5API) accountLogin(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var request AccountLoginRequest
	err := ctx.Decode(&request)
	if err != nil {
		return
	}

	decodedKey, err := base64.RawURLEncoding.DecodeString(request.Pubkey)
	if err != nil || len(decodedKey) != 33 {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidFileFormat, err), http.StatusBadRequest)
		return
	}

	if int(decodedKey[0]) != int(types.HashTypeEd25519) {
		_ = ctx.Error(NewS5Error(ErrKeyUnsupportedFileType, fmt.Errorf("public key type not supported")), http.StatusBadRequest)
		return
	}

	var challenge db.S5Challenge
	result := s.db.Where(&db.S5Challenge{Pubkey: request.Pubkey, Type: "login"}).First(&challenge)
	if result.RowsAffected == 0 || result.Error != nil {
		_ = ctx.Error(NewS5Error(ErrKeyResourceNotFound, result.Error), http.StatusNotFound)
		return
	}

	decodedResponse, err := base64.RawURLEncoding.DecodeString(request.Response)
	if err != nil || len(decodedResponse) != 65 {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidOperation, err), http.StatusBadRequest)
		return
	}

	decodedChallenge, err := base64.RawURLEncoding.DecodeString(challenge.Challenge)
	if err != nil || !bytes.Equal(decodedResponse[1:33], decodedChallenge) {
		_ = ctx.Error(NewS5Error(ErrKeyDataIntegrityError, err), http.StatusBadRequest)
		return
	}

	decodedSignature, err := base64.RawURLEncoding.DecodeString(request.Signature)
	if err != nil || !ed25519.Verify(decodedKey[1:], decodedResponse, decodedSignature) {
		_ = ctx.Error(NewS5Error(ErrKeyAuthorizationFailed, err), http.StatusUnauthorized)
		return
	}

	jwt, err := s.auth.LoginPubkey(hex.EncodeToString(decodedKey[1:]), r.RemoteAddr)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyAuthenticationFailed, err), http.StatusUnauthorized)
		return
	}

	if result := s.db.Delete(&challenge); result.Error != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, result.Error), http.StatusInternalServerError)
		return
	}

	core.SetAuthCookie(w, s.ctx, jwt)
}
func (s *S5API) accountInfo(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	userID := middleware.GetUserFromContext(r.Context())
	_, user, err := s.user.AccountExists(userID)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err), http.StatusInternalServerError)
		return
	}

	info := &AccountInfoResponse{
		Email:          user.Email,
		QuotaExceeded:  false,
		EmailConfirmed: false,
		IsRestricted:   false,
		Tier: AccountTier{
			Id:              1,
			Name:            "default",
			UploadBandwidth: math.MaxUint32,
			StorageLimit:    math.MaxUint32,
			Scopes:          []interface{}{},
		},
	}

	ctx.Encode(info)
}
func (s *S5API) accountStats(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	userID := middleware.GetUserFromContext(r.Context())
	_, user, err := s.user.AccountExists(userID)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err), http.StatusInternalServerError)
		return
	}

	info := &AccountStatsResponse{
		AccountInfoResponse: AccountInfoResponse{
			Email:          user.Email,
			QuotaExceeded:  false,
			EmailConfirmed: false,
			IsRestricted:   false,
			Tier: AccountTier{
				Id:              1,
				Name:            "default",
				UploadBandwidth: math.MaxUint32,
				StorageLimit:    math.MaxUint32,
				Scopes:          []interface{}{},
			},
		},
		Stats: AccountStats{
			Total: AccountStatsTotal{
				UsedStorage: 0,
			},
		},
	}

	ctx.Encode(info)
}

func (s *S5API) accountPinsBinary(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var cursor uint64
	err := ctx.DecodeForm("cursor", &cursor)
	if err != nil {
		return
	}

	userID := middleware.GetUserFromContext(r.Context())

	pins, err := s.pin.AccountPins(userID, cursor)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err), http.StatusInternalServerError)
		return
	}

	pinResponse := &AccountPinBinaryResponse{Cursor: cursor, Pins: pins}
	result, err := msgpack.Marshal(pinResponse)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/msgpack")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(result); err != nil {
		s.logger.Error("failed to write account pins response", zap.Error(err))
	}
}

func (s *S5API) accountPins(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	userID := middleware.GetUserFromContext(r.Context())
	pinsRet, err := s.pin.AccountPins(userID, 0)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err), http.StatusInternalServerError)
		return
	}

	tusRet, err := s.tusHandler.Uploads(r.Context(), userID)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err), http.StatusInternalServerError)
		return
	}

	pins := make([]AccountPin, len(pinsRet)+len(tusRet))

	for i, pin := range pinsRet {
		cid, err := encoding.CIDFromHash(pin.Upload.Hash, pin.Upload.Size, types.CIDTypeRaw, types.HashTypeBlake3)
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
			return
		}
		base64Url, err := cid.Hash.ToBase64Url()
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
			return
		}
		pins[i] = AccountPin{
			Hash:     base64Url,
			Size:     pin.Upload.Size,
			PinnedAt: pin.CreatedAt,
			MimeType: pin.Upload.MimeType,
		}
	}

	for i, tus := range tusRet {
		size, err := s.tusHandler.GetUploadSize(r.Context(), tus.Hash)
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
			return
		}

		cid, err := encoding.CIDFromHash(tus.Hash, uint64(size), types.CIDTypeRaw, types.HashTypeBlake3)
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
			return
		}

		base64Url, err := cid.Hash.ToBase64Url()
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
			return
		}

		pins[i+len(pinsRet)] = AccountPin{
			Hash:     base64Url,
			Size:     uint64(size),
			PinnedAt: tus.CreatedAt,
			MimeType: tus.MimeType,
		}
	}

	ctx.Encode(&AccountPinResponse{Pins: pins})
}

func (s *S5API) accountPinDelete(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	vars := mux.Vars(r)
	cid := vars["cid"]

	user := middleware.GetUserFromContext(r.Context())

	decodedCid, err := encoding.CIDFromString(cid)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidOperation, err), http.StatusBadRequest)
		return
	}

	if err := s.pin.DeletePinByHash(decodedCid.Hash.HashBytes(), user); err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
func (s *S5API) accountPin(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	vars := mux.Vars(r)
	cid := vars["cid"]

	userID := middleware.GetUserFromContext(r.Context())

	decodedCid, err := encoding.CIDFromString(cid)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidOperation, err), http.StatusBadRequest)
		return
	}

	if decodedCid.Type == types.CIDTypeResolver {
		entry, err := s.getNode().Services().Registry().Get(decodedCid.Hash.FullBytes())
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyResourceNotFound, err), http.StatusNotFound)
			return
		}

		decodedCid, err = encoding.CIDFromRegistry(entry.Data())
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
			return
		}
	}

	found := true

	if err := s.pin.PinByHash(decodedCid.Hash.HashBytes(), userID); err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err), http.StatusInternalServerError)
			return
		}
		found = false
	}

	if !found {
		err = s.pinEntity(r.Context(), userID, r.RemoteAddr, decodedCid)
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *S5API) accountPinStatus(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	vars := mux.Vars(r)
	cid := vars["cid"]

	decodedCid, err := encoding.CIDFromString(cid)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidOperation, err), http.StatusBadRequest)
		return
	}

	meta, err := s._import.GetImport(r.Context(), decodedCid.Hash.HashBytes())

	if err != nil {
		response := &AccountPinStatusResponse{
			Status:   models.ImportStatusCompleted,
			Progress: 100,
		}
		ctx.Encode(response)
		return
	}

	response := &AccountPinStatusResponse{
		Status:   meta.Status,
		Progress: meta.Progress,
	}
	ctx.Encode(response)
}

func (s *S5API) pinEntity(ctx context.Context, userId uint, userIp string, cid *encoding.CID) error {
	found := true

	if err := s.pin.PinByHash(cid.Hash.HashBytes(), userId); err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		found = false
	}

	if found {
		return nil
	}

	dlUriProvider := s.newStorageLocationProvider(&cid.Hash, true, types.StorageLocationTypeFull, types.StorageLocationTypeFile)

	err := dlUriProvider.Start()

	if err != nil {
		return err
	}

	locations, err := dlUriProvider.All()
	if err != nil {
		return err
	}

	locations = lo.FilterMap(locations, func(location s5storage.SignedStorageLocation, index int) (s5storage.SignedStorageLocation, bool) {
		r := rq.Get(location.Location().BytesURL())
		httpReq, err := r.ParseRequest()

		if err != nil {
			return nil, false
		}

		res, err := http.DefaultClient.Do(httpReq)

		if err != nil {
			err = dlUriProvider.Downvote(location)
			if err != nil {
				s.logger.Error("Error downvoting location", zap.Error(err))
				return nil, false
			}
			return nil, false
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				s.logger.Error("Error closing response body", zap.Error(err))
			}
		}(res.Body)

		// Use io.LimitedReader to limit the download size and attempt to detect if there's more data.
		limitedReader := &io.LimitedReader{R: res.Body, N: int64(s.config.Config().Core.PostUploadLimit + 1)}
		data, err := io.ReadAll(limitedReader)
		if err != nil {
			return nil, false
		}

		if !isCidManifest(cid) {
			if limitedReader.N > 0 {
				if uint64(len(data)) != cid.Size {
					return nil, false
				}
			}
		} else {
			dataCont, err := io.ReadAll(res.Body)
			if err != nil {
				return nil, false
			}

			data = append(data, dataCont...)

			proof, err := s.storage.HashObject(ctx, bytes.NewReader(data), uint64(len(data)))
			if err != nil {
				return nil, false
			}

			if !bytes.Equal(proof.Hash, cid.Hash.HashBytes()) {
				return nil, false
			}
		}

		return location, true
	})

	if len(locations) == 0 {
		return fmt.Errorf("CID could not be found on the network")
	}

	location := locations[0]

	cid64, err := cid.ToBase64Url()
	if err != nil {
		return nil
	}

	if middleware.CtxAborted(ctx) {
		return ctx.Err()
	}

	err = s._import.SaveImport(ctx, core.ImportMetadata{
		UserID:     userId,
		Hash:       cid.Hash.HashBytes(),
		Protocol:   s5.GetStorageProtocol(s.protocol).Name(),
		ImporterIP: userIp,
	}, true)
	if err != nil {
		return err
	}
	err = s.cron.CreateJobIfNotExists(define.CronTaskPinImportValidateName, define.CronTaskPinImportValidateArgs{
		Cid:      cid64,
		Url:      location.Location().BytesURL(),
		ProofUrl: location.Location().OutboardBytesURL(),
		UserId:   userId,
	}, []string{cid64})

	if err != nil {
		return err
	}

	return nil
}

type dirTryFiles []string
type dirErrorPages map[int]string

func (d *dirTryFiles) UnmarshalText(data []byte) error {
	var out []string

	err := json.Unmarshal(data, &out)
	if err != nil {
		return err
	}

	*d = out

	return nil
}

func (d *dirErrorPages) UnmarshalText(data []byte) error {
	var out map[int]string

	err := json.Unmarshal(data, &out)
	if err != nil {
		return err
	}

	*d = out

	return nil
}

func (s *S5API) directoryUpload(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	// Decode form fields
	var (
		tryFiles   dirTryFiles
		errorPages dirErrorPages
		name       string
	)

	err := ctx.DecodeForm("tryFiles", &tryFiles)
	if err != nil {
		return
	}

	err = ctx.DecodeForm("errorPages", &errorPages)
	if err != nil {
		return
	}

	err = ctx.DecodeForm("name", &name)
	if err != nil {
		return
	}

	// Verify content type
	if contentType := r.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "multipart/form-data") {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidOperation, fmt.Errorf("expected multipart/form-data content type, got %s", contentType)), http.StatusBadRequest)
		return
	}

	uploads, err := s.processMultipartFiles(r)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	var webappErrorPages s5libmetadata.WebAppErrorPages

	for code, page := range errorPages {
		webappErrorPages[code] = page
	}

	// Generate metadata for the directory upload
	app, err := s.createAppMetadata(name, tryFiles, webappErrorPages, uploads)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	// Upload the metadata
	cidStr, err := s.uploadAppMetadata(app, r)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	response := &AppUploadResponse{CID: cidStr}
	ctx.Encode(response)
}

func (s *S5API) processMultipartFiles(r *http.Request) (map[string]*core.UploadMetadata, error) {
	uploadMap := make(map[string]*core.UploadMetadata)
	user := middleware.GetUserFromContext(r.Context())

	for _, files := range r.MultipartForm.File {
		for _, fileHeader := range files {
			filename := extractMPFilename(fileHeader.Header)
			if filename == "" {
				return nil, NewS5Error(ErrKeyInvalidOperation, fmt.Errorf("filename not found in multipart file header"))
			}

			file, err := fileHeader.Open()
			if err != nil {
				return nil, NewS5Error(ErrKeyStorageOperationFailed, err)
			}
			defer func(file multipart.File) {
				err := file.Close()
				if err != nil {
					s.logger.Error("Error closing file", zap.Error(err))
				}
			}(file)

			upload, err := s.storage.UploadObject(r.Context(), s5.GetStorageProtocol(s.protocol), file, uint64(fileHeader.Size), nil, nil)
			if err != nil {
				return nil, NewS5Error(ErrKeyStorageOperationFailed, err)
			}

			upload.UserID = user
			upload.UploaderIP = r.RemoteAddr

			err = s.metadata.SaveUpload(r.Context(), *upload, true)
			if err != nil {
				return nil, NewS5Error(ErrKeyStorageOperationFailed, err)
			}

			err = s.pin.PinByHash(upload.Hash, user)
			if err != nil {
				return nil, NewS5Error(ErrKeyStorageOperationFailed, err)
			}

			err = s.sync.Update(*upload)

			if err != nil {
				return nil, err
			}

			uploadMap[filename] = upload
		}
	}

	return uploadMap, nil
}

func (s *S5API) createAppMetadata(name string, tryFiles []string, errorPages s5libmetadata.WebAppErrorPages, uploads map[string]*core.UploadMetadata) (*s5libmetadata.WebAppMetadata, error) {
	filesMap := s5libmetadata.NewWebAppFileMap()

	for filename, upload := range uploads {
		hash := upload.Hash

		cid, err := encoding.CIDFromHash(hash, upload.Size, types.CIDTypeRaw, types.HashTypeBlake3)
		if err != nil {
			return nil, NewS5Error(ErrKeyInternalError, err, "Failed to create CID for file: "+filename)
		}
		filesMap.Put(filename, s5libmetadata.WebAppMetadataFileReference{
			Cid:         cid,
			ContentType: upload.MimeType,
		})
	}

	filesMap.Sort()

	extraMetadataMap := make(map[int]interface{})
	for statusCode, page := range errorPages {
		extraMetadataMap[statusCode] = page
	}

	extraMetadata := s5libmetadata.NewExtraMetadata(extraMetadataMap)
	// Create the web app metadata object
	app := s5libmetadata.NewWebAppMetadata(
		name,
		tryFiles,
		*extraMetadata,
		errorPages,
		filesMap,
	)

	return app, nil
}

func (s *S5API) uploadAppMetadata(appData *s5libmetadata.WebAppMetadata, r *http.Request) (string, error) {
	userId := middleware.GetUserFromContext(r.Context())

	appDataRaw, err := msgpack.Marshal(appData)
	if err != nil {
		return "", NewS5Error(ErrKeyInternalError, err, "Failed to marshal app s5libmetadata")
	}

	file := bytes.NewReader(appDataRaw)

	upload, err := s.storage.UploadObject(r.Context(), s5.GetStorageProtocol(s.protocol), file, uint64(len(appDataRaw)), nil, nil)
	if err != nil {
		return "", NewS5Error(ErrKeyStorageOperationFailed, err)
	}

	upload.UserID = userId
	upload.UploaderIP = r.RemoteAddr

	err = s.metadata.SaveUpload(r.Context(), *upload, true)
	if err != nil {
		return "", NewS5Error(ErrKeyStorageOperationFailed, err)
	}

	err = s.pin.PinByHash(upload.Hash, userId)
	if err != nil {
		return "", NewS5Error(ErrKeyStorageOperationFailed, err)
	}

	// Construct the CID for the newly uploaded s5libmetadata
	cid, err := encoding.CIDFromHash(upload.Hash, uint64(len(appDataRaw)), types.CIDTypeMetadataWebapp, types.HashTypeBlake3)
	if err != nil {
		return "", NewS5Error(ErrKeyInternalError, err, "Failed to create CID for new app s5libmetadata")
	}
	cidStr, err := cid.ToString()
	if err != nil {
		return "", NewS5Error(ErrKeyInternalError, err, "Failed to convert CID to string for new app s5libmetadata")
	}

	return cidStr, nil
}

func (s *S5API) debugDownloadUrls(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	vars := mux.Vars(r)
	cid := vars["cid"]

	decodedCid, err := encoding.CIDFromString(cid)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidOperation, err, "Failed to decode CID"), http.StatusBadRequest)
		return
	}

	s5node := s.getNode()
	dlUriProvider := s.newStorageLocationProvider(&decodedCid.Hash, false, types.StorageLocationTypeFull, types.StorageLocationTypeFile, types.StorageLocationTypeBridge)

	if err := dlUriProvider.Start(); err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err, "Failed to start URI provider"), http.StatusInternalServerError)
		return
	}

	locations, err := s5node.Services().Storage().GetCachedStorageLocations(&decodedCid.Hash, []types.StorageLocationType{
		types.StorageLocationTypeFull, types.StorageLocationTypeFile, types.StorageLocationTypeBridge,
	}, true)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err, "Failed to get cached storage locations"), http.StatusInternalServerError)
		return
	}

	availableNodes := lo.Keys[string, s5storage.StorageLocation](locations)
	availableNodesIds := make([]*encoding.NodeId, len(availableNodes))

	for i, nodeIdStr := range availableNodes {
		nodeId, err := encoding.DecodeNodeId(nodeIdStr)
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyInternalError, err, "Failed to decode node ID"), http.StatusInternalServerError)
			return
		}
		availableNodesIds[i] = nodeId
	}

	sorted, err := s5node.Services().P2P().SortNodesByScore(availableNodesIds)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyNetworkError, err, "Failed to sort nodes by score"), http.StatusInternalServerError)
		return
	}

	output := make([]string, len(sorted))
	for i, nodeId := range sorted {
		nodeIdStr, err := nodeId.ToString()
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyInternalError, err, "Failed to convert node ID to string"), http.StatusInternalServerError)
			return
		}
		output[i] = locations[nodeIdStr].BytesURL()
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(strings.Join(output, "\n")))
	if err != nil {
		s.logger.Error("Failed to write response", zap.Error(err))
	}
}

func (s *S5API) registryQuery(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var pk string
	err := ctx.DecodeForm("pk", &pk)
	if err != nil {
		return
	}

	pkBytes, err := base64.RawURLEncoding.DecodeString(pk)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidFileFormat, err), http.StatusBadRequest)
		return
	}

	entry, err := s.getNode().Services().Registry().Get(pkBytes)
	if err != nil {
		s5ErrKey := ErrKeyStorageOperationFailed
		_ = ctx.Error(NewS5Error(s5ErrKey, err), http.StatusInternalServerError)
		return
	}

	if entry == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	response := RegistryQueryResponse{
		Pk:        base64.RawURLEncoding.EncodeToString(entry.PK()),
		Revision:  entry.Revision(),
		Data:      base64.RawURLEncoding.EncodeToString(entry.Data()),
		Signature: base64.RawURLEncoding.EncodeToString(entry.Signature()),
	}
	ctx.Encode(response)
}

func (s *S5API) registrySet(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var request RegistrySetRequest
	if err := ctx.Decode(&request); err != nil {
		return
	}

	pk, err := base64.RawURLEncoding.DecodeString(request.Pk)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidFileFormat, err, "Error decoding public key"), http.StatusBadRequest)
		return
	}

	data, err := base64.RawURLEncoding.DecodeString(request.Data)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidFileFormat, err, "Error decoding data"), http.StatusBadRequest)
		return
	}

	signature, err := base64.RawURLEncoding.DecodeString(request.Signature)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidFileFormat, err, "Error decoding signature"), http.StatusBadRequest)
		return
	}

	entry := protocol.NewSignedRegistryEntry(pk, request.Revision, data, signature)

	err = s.getNode().Services().Registry().Set(entry, false, nil)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err, "Error setting registry entry"), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *S5API) registrySubscription(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	// Create a context for the WebSocket operations
	wsCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var listeners []func()

	// Accept the WebSocket connection
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
		return
	}
	defer func() {
		// Close the WebSocket connection gracefully
		err := c.Close(websocket.StatusNormalClosure, "connection closed")
		if err != nil {
			s.logger.Error("error closing websocket connection", zap.Error(err))
		}
		// Clean up all listeners when the connection is closed
		for _, listener := range listeners {
			listener()
		}
	}()

	// Main loop for reading messages
	for {
		_, data, err := c.Read(wsCtx)
		if err != nil {
			if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
				// Normal closure
				s.logger.Info("websocket connection closed normally")
			} else {
				// Handle different types of errors
				_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
			}
			break
		}

		decoder := msgpack.NewDecoder(bytes.NewReader(data))

		// Assuming method indicates the type of operation, validate it
		method, err := decoder.DecodeInt()
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
			continue
		}

		if method != 2 {
			_ = ctx.Error(NewS5Error(ErrKeyInvalidOperation, fmt.Errorf("invalid method")), http.StatusBadRequest)
			continue
		}

		sre, err := decoder.DecodeBytes()
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
			continue
		}

		// Listen for updates on the registry entry and send updates via WebSocket
		off, err := s.getNode().Services().Registry().Listen(sre, func(entry protocol.SignedRegistryEntry) {
			encoded, err := msgpack.Marshal(entry)
			if err != nil {
				s.logger.Error("error encoding entry", zap.Error(err))
				return
			}

			// Write updates to the WebSocket connection
			if err := c.Write(wsCtx, websocket.MessageBinary, encoded); err != nil {
				s.logger.Error("error writing to websocket", zap.Error(err))
			}
		})
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyInternalError, err), http.StatusInternalServerError)
			break
		}

		listeners = append(listeners, off) // Add the listener's cleanup function to the list
	}
}

func (s *S5API) getNode() *node.Node {
	return s.protocol.Node()
}

func (s *S5API) downloadBlob(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	vars := mux.Vars(r)
	cid := vars["cid"]

	cid = strings.Split(cid, ".")[0]

	cidDecoded, err := encoding.CIDFromString(cid)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidOperation, err, "error decoding cid"), http.StatusBadRequest)
		return
	}

	dlUriProvider := s.newStorageLocationProvider(&cidDecoded.Hash, true, types.StorageLocationTypeFull, types.StorageLocationTypeFile, types.StorageLocationTypeBridge)

	err = dlUriProvider.Start()
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err, "error starting search"), http.StatusInternalServerError)
		return
	}

	next, err := dlUriProvider.Next()
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err, "error fetching blob"), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, next.Location().BytesURL(), http.StatusFound)
}

func (s *S5API) debugStorageLocations(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	vars := mux.Vars(r)
	hash := vars["hash"]

	kinds := r.FormValue("kinds")

	decodedHash, err := encoding.MultihashFromBase64Url(hash)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidOperation, err, "error decoding hash"), http.StatusBadRequest)
		return
	}

	typeList := strings.Split(kinds, ",")
	typeIntList := make([]types.StorageLocationType, 0)

	for _, typeStr := range typeList {
		typeInt, err := strconv.Atoi(typeStr)
		if err != nil {
			continue
		}
		typeIntList = append(typeIntList, types.StorageLocationType(typeInt))
	}

	if len(typeIntList) == 0 {
		typeIntList = []types.StorageLocationType{
			types.StorageLocationTypeFull,
			types.StorageLocationTypeFile,
			types.StorageLocationTypeBridge,
			types.StorageLocationTypeArchive,
		}
	}

	dlUriProvider := s.newStorageLocationProvider(decodedHash, false, typeIntList...)

	err = dlUriProvider.Start()
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err, "error starting search"), http.StatusInternalServerError)
		return
	}

	_, err = dlUriProvider.Next()
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err, "error fetching locations"), http.StatusInternalServerError)
		return
	}

	locations, err := s.getNode().Services().Storage().GetCachedStorageLocations(decodedHash, typeIntList, true)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err, "error getting cached locations"), http.StatusInternalServerError)
		return
	}

	availableNodes := lo.Keys[string, s5storage.StorageLocation](locations)
	availableNodesIds := make([]*encoding.NodeId, len(availableNodes))

	for i, nodeIdStr := range availableNodes {
		nodeId, err := encoding.DecodeNodeId(nodeIdStr)
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyInternalError, err, "error decoding node id"), http.StatusInternalServerError)
			return
		}
		availableNodesIds[i] = nodeId
	}

	availableNodesIds, err = s.getNode().Services().P2P().SortNodesByScore(availableNodesIds)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyNetworkError, err, "error sorting nodes"), http.StatusInternalServerError)
		return
	}

	debugLocations := make([]DebugStorageLocation, len(availableNodes))

	for i, nodeId := range availableNodesIds {
		nodeIdStr, err := nodeId.ToBase58()
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyInternalError, err, "error encoding node id"), http.StatusInternalServerError)
			return
		}

		score, err := s.getNode().Services().P2P().GetNodeScore(nodeId)
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyNetworkError, err, "error getting node score"), http.StatusInternalServerError)
			return
		}

		debugLocations[i] = DebugStorageLocation{
			Type:   locations[nodeIdStr].Type(),
			Parts:  locations[nodeIdStr].Parts(),
			Expiry: locations[nodeIdStr].Expiry(),
			NodeId: nodeIdStr,
			Score:  score,
		}
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(&DebugStorageLocationsResponse{
		Locations: debugLocations,
	}); err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInternalError, err, "error encoding response"), http.StatusInternalServerError)
		return
	}
}
func (s *S5API) downloadMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	vars := mux.Vars(r)
	cid := vars["cid"]

	cidDecoded, err := encoding.CIDFromString(cid)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyInvalidOperation, err, "error decoding cid"), http.StatusBadRequest)
		s.logger.Error("error decoding cid", zap.Error(err))
		return
	}

	switch cidDecoded.Type {
	case types.CIDTypeRaw:
		_ = ctx.Error(NewS5Error(ErrKeyInvalidOperation, errors.New("Raw CIDs do not have metadata")), http.StatusUnsupportedMediaType)
		return
	case types.CIDTypeResolver:
		_ = ctx.Error(NewS5Error(ErrKeyInvalidOperation, errors.New("Resolver CIDs not yet supported")), http.StatusUnsupportedMediaType)
		return
	}

	meta, err := s.getNode().Services().Storage().GetMetadataByCID(cidDecoded)
	if err != nil {
		_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err, "error getting metadata"), http.StatusInternalServerError)
		s.logger.Error("error getting metadata", zap.Error(err))
		return
	}

	if cidDecoded.Type != types.CIDTypeBridge {
		w.Header().Set("Cache-Control", "public, max-age=31536000")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=60")
	}

	ctx.Encode(&meta)
}
func (s *S5API) downloadFile(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	vars := mux.Vars(r)
	cid := vars["cid"]

	var hashBytes []byte
	var typ types.CIDType
	isProof := false

	if strings.HasSuffix(cid, core.PROOF_EXTENSION) {
		isProof = true
		cid = strings.TrimSuffix(cid, core.PROOF_EXTENSION)
	}

	cidDecoded, err := encoding.CIDFromString(cid)
	if err != nil {
		hashDecoded, err := encoding.MultihashFromBase64Url(cid)
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyInvalidOperation, err, "error decoding as cid or hash"), http.StatusBadRequest)
			return
		}
		hashBytes = hashDecoded.HashBytes()
	} else {
		hashBytes = cidDecoded.Hash.HashBytes()
		typ = cidDecoded.Type
	}

	file := s.newFile(r.Context(), FileParams{
		Hash: hashBytes,
		Type: typ,
	})

	if !file.Exists() {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	defer func(file io.ReadCloser) {
		err := file.Close()
		if err != nil {
			s.logger.Error("error closing file", zap.Error(err))
		}
	}(file)

	if isProof {
		proof, err := file.Proof()
		if err != nil {
			_ = ctx.Error(NewS5Error(ErrKeyStorageOperationFailed, err, "error getting proof"), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, fmt.Sprintf("%.obao", file.Name()), file.Modtime(), bytes.NewReader(proof))
		return
	}

	var mimeType string

	if len(file.Mime()) > 0 {
		mimeType = file.Mime()
	}

	if len(mimeType) == 0 {
		detectedType, err := mimetype.DetectReader(file)
		if err != nil {
			s.logger.Error("error detecting mime type", zap.Error(err))
			_ = ctx.Error(err, http.StatusInternalServerError)
			return
		}
		mimeType = detectedType.String()
		_, err = file.Seek(0, io.SeekStart)
		if err != nil {
			s.logger.Error("error seeking file", zap.Error(err))
			_ = ctx.Error(err, http.StatusInternalServerError)
			return
		}
	}

	if len(mimeType) == 0 {
		mimeType = "application/octet-stream"
	}

	w.Header().Set("Content-Type", mimeType)

	http.ServeContent(w, r, file.Name(), file.Modtime(), file)
}

func (s *S5API) sendErrorResponse(w http.ResponseWriter, err error) {
	var statusCode int

	switch e := err.(type) {
	case *S5Error:
		statusCode = e.HttpStatus()
	case *core.AccountError:
		mappedCode, ok := core.ErrorCodeToHttpStatus[e.Key]
		if !ok {
			statusCode = http.StatusInternalServerError
		} else {
			statusCode = mappedCode
		}
	default:
		statusCode = http.StatusInternalServerError
		err = errors.New("An internal server error occurred.")
	}

	http.Error(w, err.Error(), statusCode)
}

func (s *S5API) newStorageLocationProvider(hash *encoding.Multihash, excludeSelf bool, types ...types.StorageLocationType) s5storage.StorageLocationProvider {

	excludeNodes := make([]*encoding.NodeId, 0)

	if excludeSelf {
		excludeNodes = append(excludeNodes, s.getNode().NodeId())
	}

	return provider.NewStorageLocationProvider(provider.StorageLocationProviderParams{
		Services:      s.getNode().Services(),
		Hash:          hash,
		LocationTypes: types,
		ServiceParams: service.ServiceParams{
			Logger: s.logger.Logger,
			Config: s.getNode().Config(),
			Db:     s.getNode().Db(),
		},
		ExcludeNodes: excludeNodes,
	})
}

func (s *S5API) newFile(ctx context.Context, params FileParams) *S5File {
	params.Context = s.ctx
	params.ReqContext = ctx
	params.Protocol = s.protocol
	params.Tus = s.tusHandler

	return NewFile(params)
}

func (s *S5API) pinImportCronJob(cid string, url string, proofUrl string, userId uint) error {
	ctx := context.Background()
	totalStages := 3

	// Parse CID early to avoid unnecessary operations if it fails.
	parsedCid, err := encoding.CIDFromString(cid)
	if err != nil {
		s.logger.Error("error parsing cid", zap.Error(err))
		return err
	}

	err = s._import.UpdateStatus(ctx, parsedCid.Hash.HashBytes(), models.ImportStatusProcessing)
	if err != nil {
		return err
	}

	// Function to streamline error handling and closing of response body.
	closeBody := func(body io.ReadCloser) {
		if err := body.Close(); err != nil {
			s.logger.Error("error closing response body", zap.Error(err))
		}
	}

	// Inline fetching and reading body, directly incorporating your checks.
	fetchAndProcess := func(fetchUrl string, progressStage int) ([]byte, error) {
		req, err := rq.Get(fetchUrl).ParseRequest()
		if err != nil {
			s.logger.Error("error parsing request", zap.Error(err))
			return nil, err
		}

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			s.logger.Error("error executing request", zap.Error(err))
			return nil, err
		}

		defer closeBody(res.Body)

		if res.StatusCode != http.StatusOK {
			errMsg := "error fetching URL: " + fetchUrl
			s.logger.Error(errMsg, zap.String("status", res.Status))
			return nil, fmt.Errorf(errMsg+" with status: %s", res.Status)
		}

		data, err := io.ReadAll(res.Body)
		if err != nil {
			s.logger.Error("error reading response body", zap.Error(err))
			return nil, err
		}

		err = s._import.UpdateProgress(ctx, parsedCid.Hash.HashBytes(), progressStage, totalStages)
		if err != nil {
			return nil, err
		}

		return data, nil
	}

	saveAndPin := func(upload *core.UploadMetadata) error {
		err = s._import.UpdateProgress(ctx, parsedCid.Hash.HashBytes(), 3, totalStages)
		if err != nil {
			return err
		}

		upload.UserID = userId
		if err := s.metadata.SaveUpload(ctx, *upload, true); err != nil {
			return err
		}

		if err := s.pin.PinByHash(upload.Hash, userId); err != nil {
			return err
		}

		err = s._import.DeleteImport(ctx, upload.Hash)
		if err != nil {
			return err
		}

		return nil
	}
	// Fetch file and process if under post upload limit.
	if parsedCid.Size <= s.config.Config().Core.PostUploadLimit {
		fileData, err := fetchAndProcess(url, 1)
		if err != nil {
			return err // Error logged in fetchAndProcess
		}

		hash, err := s.storage.HashObject(ctx, bytes.NewReader(fileData), uint64(len(fileData)))
		if err != nil {
			s.logger.Error("error hashing object", zap.Error(err))
			return err
		}

		if !bytes.Equal(hash.Hash, parsedCid.Hash.HashBytes()) {
			return fmt.Errorf("hash mismatch")
		}

		err = s._import.UpdateProgress(ctx, parsedCid.Hash.HashBytes(), 2, totalStages)
		if err != nil {
			return err
		}

		upload, err := s.storage.UploadObject(ctx, s5.GetStorageProtocol(s.protocol), bytes.NewReader(fileData), parsedCid.Size, nil, hash)
		if err != nil {
			return err
		}

		err = saveAndPin(upload)
		if err != nil {
			return err
		}

		return nil
	}

	// Fetch proof.
	proof, err := fetchAndProcess(proofUrl, 1)
	if err != nil {
		return err
	}

	baoProof := bao.Result{
		Hash:   parsedCid.Hash.HashBytes(),
		Proof:  proof,
		Length: uint(parsedCid.Size),
	}

	client, err := s.storage.S3Client(ctx)
	if err != nil {
		s.logger.Error("error getting s3 client", zap.Error(err))
		return err
	}

	req, err := rq.Get(url).ParseRequest()
	if err != nil {
		s.logger.Error("error parsing request", zap.Error(err))
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("error executing request", zap.Error(err))
		return err
	}
	defer closeBody(res.Body)

	verifier := bao.NewVerifier(res.Body, baoProof, s.logger.Logger)
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			s.logger.Error("error closing verifier stream", zap.Error(err))
		}

	}(verifier)

	if parsedCid.Size < core.S3_MULTIPART_MIN_PART_SIZE {
		_, err = client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:        aws.String(s.config.Config().Core.Storage.S3.BufferBucket),
			Key:           aws.String(cid),
			Body:          verifier,
			ContentLength: aws.Int64(int64(parsedCid.Size)),
		})
		if err != nil {
			s.logger.Error("error uploading object", zap.Error(err))
			return err
		}
	} else {
		err := s.storage.S3MultipartUpload(ctx, verifier, s.config.Config().Core.Storage.S3.BufferBucket, cid, parsedCid.Size)
		if err != nil {
			s.logger.Error("error uploading object", zap.Error(err))
			return err
		}
	}

	err = s._import.UpdateProgress(ctx, parsedCid.Hash.HashBytes(), 2, totalStages)
	if err != nil {
		return err
	}

	upload, err := s.storage.UploadObject(ctx, s5.GetStorageProtocol(s.protocol), nil, 0, &core.MultiPartUploadParams{
		ReaderFactory: func(start uint, end uint) (io.ReadCloser, error) {
			rangeHeader := "bytes=%d-"
			if end != 0 {
				rangeHeader += "%d"
				rangeHeader = fmt.Sprintf("bytes=%d-%d", start, end)
			} else {
				rangeHeader = fmt.Sprintf("bytes=%d-", start)
			}
			object, err := client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(s.config.Config().Core.Storage.S3.BufferBucket),
				Key:    aws.String(cid),
				Range:  aws.String(rangeHeader),
			})

			if err != nil {
				return nil, err
			}

			return object.Body, nil
		},
		Bucket:          s.config.Config().Core.Storage.S3.BufferBucket,
		FileName:        s5.GetStorageProtocol(s.protocol).EncodeFileName(parsedCid.Hash.HashBytes()),
		Size:            parsedCid.Size,
		UploadIDHandler: nil,
	}, &baoProof)

	if err != nil {
		s.logger.Error("error uploading object", zap.Error(err))
		return err
	}

	err = saveAndPin(upload)
	if err != nil {
		return err
	}

	return nil
}

func (s *S5API) Domain() string {
	return "s5"
}

func (s *S5API) AuthTokenName() string {
	return "s5-auth-token"
}

func (s *S5API) Configure(router *mux.Router) error {
	// Middleware functions
	authMiddlewareOpts := middleware.AuthMiddlewareOptions{
		Context: s.ctx,
		Purpose: core.JWTPurposeLogin,
	}

	authMw := authMiddleware(authMiddlewareOpts)
	tusCors := cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool {
			return true
		},
		AllowedMethods: []string{"GET", "POST", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowedHeaders: []string{
			"Authorization",
			"Expires",
			"Upload-Concat",
			"Upload-Length",
			"Upload-Metadata",
			"Upload-Offset",
			"X-Requested-With",
			"Tus-Version",
			"Tus-Resumable",
			"Tus-Extension",
			"Tus-Max-Size",
			"X-HTTP-Method-Override",
			"Content-Type",
		},
		AllowCredentials: true,
	})
	defaultCors := cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool {
			return true
		},
		AllowedMethods:   []string{"POST", "GET", "DELETE"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})
	debugCors := cors.Default()

	err := swagger.Swagger(swagSpec, router)
	if err != nil {
		return err
	}

	// Apply middleware at the router level
	router.Use(muxHandlers.ProxyHeaders)

	s5handlers := s.protocol.Node().Services().HTTP().GetHttpRouter()

	for path, h := range s5handlers {
		fs := strings.Fields(path)
		if len(fs) != 2 {
			panic(fmt.Sprintf("invalid route %q", path))
		}
		method, _path := fs[0], fs[1]

		router.HandleFunc(_path, h).Methods(method)
	}

	// Account API
	accountRouter := router.PathPrefix("/s5/account").Subrouter()
	accountRouterAuthed := accountRouter.PathPrefix("").Subrouter()

	// Authed routes
	accountRouterAuthed.Use(authMw)

	accountRouterAuthed.HandleFunc("", s.accountInfo).Methods(http.MethodGet)
	accountRouterAuthed.HandleFunc("/stats", s.accountStats).Methods(http.MethodGet)
	accountRouterAuthed.HandleFunc("/pins.bin", s.accountPinsBinary).Methods(http.MethodGet)
	accountRouterAuthed.HandleFunc("/pins", s.accountPins).Methods(http.MethodGet)

	// Unauthed routes
	accountRouter.HandleFunc("/register", s.accountRegisterChallenge).Methods(http.MethodGet)
	accountRouter.HandleFunc("/register", s.accountRegister).Methods(http.MethodPost)
	accountRouter.HandleFunc("/login", s.accountLoginChallenge).Methods(http.MethodGet)
	accountRouter.HandleFunc("/login", s.accountLogin).Methods(http.MethodPost)

	// Upload API
	uploadRouter := router.PathPrefix("/s5/upload").Subrouter()
	uploadRouter.Use(authMw, defaultCors.Handler)
	uploadRouter.HandleFunc("", s.smallFileUpload).Methods(http.MethodPost)
	uploadRouter.HandleFunc("/directory", s.directoryUpload).Methods(http.MethodPost)

	// Tus API
	tusRouter := router.PathPrefix("/s5/upload/tus").Subrouter()
	tusRouter.Use(tusCors.Handler, authMw, tusMiddleware(s.tusHandler))
	tusRouter.HandleFunc("", nil).Methods(http.MethodPost, http.MethodOptions)
	tusRouter.HandleFunc("/{id}", nil).Methods(http.MethodHead, http.MethodPost, http.MethodPatch, http.MethodOptions)

	// Download API
	downloadRouter := router.PathPrefix("/s5").Subrouter()
	downloadRouter.Use(defaultCors.Handler)
	downloadRouter.HandleFunc("/blob/{cid}", s.downloadBlob).Methods(http.MethodGet).Use(authMw)
	downloadRouter.HandleFunc("/metadata/{cid}", s.downloadMetadata).Methods(http.MethodGet)
	downloadRouter.HandleFunc("/download/{cid}", s.downloadFile).Methods(http.MethodGet)

	// Pins API
	pinRouter := router.PathPrefix("/s5").Subrouter()
	pinRouter.Use(authMw, defaultCors.Handler)
	pinRouter.HandleFunc("/pin/{cid}", s.accountPin).Methods(http.MethodPost)
	pinRouter.HandleFunc("/pin/{cid}/status", s.accountPinStatus).Methods(http.MethodGet)
	pinRouter.HandleFunc("/delete/{cid}", s.accountPinDelete).Methods(http.MethodDelete)

	// Debug API
	debugRouter := router.PathPrefix("/s5/debug").Subrouter()
	debugRouter.Handle("/download_urls/{cid}", debugCors.Handler(http.HandlerFunc(s.debugDownloadUrls))).Methods(http.MethodGet)
	debugRouter.Handle("/storage_locations/{hash}", debugCors.Handler(http.HandlerFunc(s.debugStorageLocations))).Methods(http.MethodGet)

	// Registry API
	registryRouter := router.PathPrefix("/s5/registry").Subrouter()
	registryRouter.Use(authMw)
	registryRouter.HandleFunc("", s.registryQuery).Methods(http.MethodGet)
	registryRouter.HandleFunc("", s.registrySet).Methods(http.MethodPost)
	registryRouter.HandleFunc("/subscription", s.registrySubscription).Methods(http.MethodGet)

	// CORS
	router.PathPrefix("").Use(defaultCors.Handler).Methods(http.MethodOptions).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	})

	return nil
}

func isCidManifest(cid *encoding.CID) bool {
	mTypes := []types.CIDType{
		types.CIDTypeMetadataMedia,
		types.CIDTypeMetadataWebapp,
		types.CIDTypeUserIdentity,
		types.CIDTypeDirectory,
	}

	return slices.Contains(mTypes, cid.Type)
}

func extractMPFilename(header textproto.MIMEHeader) string {
	cd := header.Get("Content-Disposition")
	if cd == "" {
		return ""
	}

	_, params, err := mime.ParseMediaType(cd)
	if err != nil {
		return ""
	}

	filename := params["filename"]
	if filename == "" {
		return ""
	}

	return filename
}
