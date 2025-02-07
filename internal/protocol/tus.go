package protocol

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/tus/tusd/v2/pkg/s3store"
	"go.lumeweb.com/libs5-go/encoding"
	"go.lumeweb.com/portal-plugin-s5/internal/cron/define"
	"go.lumeweb.com/portal/config"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db/models"
	"go.lumeweb.com/portal/middleware"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"io"
	"log/slog"

	"github.com/tus/tusd-etcd3-locker/pkg/etcd3locker"
	"github.com/tus/tusd/v2/pkg/handler"
	"go.uber.org/zap/exp/zapslog"
	"time"
)

type CtxRangeKeyType string

const CtxRangeKey CtxRangeKeyType = "range"

type TusHandler struct {
	ctx             core.Context
	config          config.Manager
	db              *gorm.DB
	logger          *core.Logger
	cron            core.CronService
	storage         core.StorageService
	users           core.UserService
	metadata        core.MetadataService
	tus             *handler.Handler
	tusStore        handler.DataStore
	s3Client        *s3.Client
	storageProtocol core.StorageProtocol
}

func NewTusHandler() (*TusHandler, []core.ContextBuilderOption) {
	th := &TusHandler{}

	opts := core.ContextOptions(
		core.ContextWithStartupFunc(func(context core.Context) error {
			th.ctx = context
			th.config = context.Config()
			th.db = context.DB()
			th.logger = context.Logger()
			th.cron = context.Service(core.CRON_SERVICE).(core.CronService)
			th.storage = context.Service(core.STORAGE_SERVICE).(core.StorageService)
			th.users = context.Service(core.USER_SERVICE).(core.UserService)
			th.metadata = context.Service(core.METADATA_SERVICE).(core.MetadataService)
			return nil
		}),
		core.ContextWithStartupFunc(func(context core.Context) error {
			err := th.Init()
			if err != nil {
				return err
			}
			return nil
		}),
		core.ContextWithStartupFunc(func(context core.Context) error {
			th.worker()
			return nil
		}),
	)

	return th, opts
}

func (t *TusHandler) Init() error {
	preUpload := func(hook handler.HookEvent) (handler.HTTPResponse, handler.FileInfoChanges, error) {
		blankResp := handler.HTTPResponse{}
		blankChanges := handler.FileInfoChanges{}

		hash, ok := hook.Upload.MetaData["hash"]
		if !ok {
			return blankResp, blankChanges, errors.New("missing hash")
		}

		decodedHash, err := encoding.MultihashFromBase64Url(hash)

		if err != nil {
			return blankResp, blankChanges, err
		}

		upload, err := t.metadata.GetUpload(hook.Context, decodedHash.HashBytes())

		if !upload.IsEmpty() {
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return blankResp, blankChanges, err
			}
			return blankResp, blankChanges, errors.New("file already exists")
		}

		return blankResp, blankChanges, nil
	}

	s3Client, err := t.storage.S3Client(context.Background())
	if err != nil {
		return err
	}

	store := s3store.New(t.config.Config().Core.Storage.S3.BufferBucket, s3Client)

	locker, err := getLocker(t.config, t.db, t.logger)
	if err != nil {
		return err
	}

	composer := handler.NewStoreComposer()
	store.UseIn(composer)

	if locker != nil {
		composer.UseLocker(locker)
	}

	handlr, err := handler.NewHandler(handler.Config{
		BasePath:                "/s5/upload/tus",
		StoreComposer:           composer,
		DisableDownload:         true,
		NotifyCompleteUploads:   true,
		NotifyTerminatedUploads: true,
		NotifyCreatedUploads:    true,
		RespectForwardedHeaders: true,
		PreUploadCreateCallback: preUpload,
		Logger:                  slog.New(zapslog.NewHandler(t.logger.Core(), nil)),
	})

	if err != nil {
		return err
	}

	t.tus = handlr
	t.tusStore = store
	t.s3Client = s3Client

	return nil
}

func (t *TusHandler) Tus() *handler.Handler {
	return t.tus
}

func (t *TusHandler) TusStore() handler.DataStore {
	return t.tusStore
}

func (t *TusHandler) S3Client() *s3.Client {
	return t.s3Client
}

func (t *TusHandler) UploadExists(ctx context.Context, id string) (bool, models.TusUpload) {
	var upload models.TusUpload
	result := t.db.WithContext(ctx).Model(&models.TusUpload{}).Where(&models.TusUpload{UploadID: id}).First(&upload)

	return result.RowsAffected > 0, upload
}

func (t *TusHandler) UploadHashExists(ctx context.Context, hash []byte) (bool, models.TusUpload) {
	var upload models.TusUpload
	result := t.db.WithContext(ctx).Model(&models.TusUpload{}).Where(&models.TusUpload{Hash: hash}).First(&upload)

	return result.RowsAffected > 0, upload
}

func (t *TusHandler) Uploads(ctx context.Context, uploaderID uint) ([]models.TusUpload, error) {
	var uploads []models.TusUpload
	result := t.db.WithContext(ctx).Model(&models.TusUpload{}).Where(&models.TusUpload{UploaderID: uploaderID}).Find(&uploads)

	if result.Error != nil {
		return nil, result.Error
	}

	return uploads, nil
}

func (t *TusHandler) CreateUpload(ctx context.Context, hash []byte, uploadID string, uploaderID uint, uploaderIP string, protocol string, mimeType string) (*models.TusUpload, error) {
	upload := &models.TusUpload{
		Hash:       hash,
		UploadID:   uploadID,
		UploaderID: uploaderID,
		UploaderIP: uploaderIP,
		Uploader:   models.User{},
		Protocol:   protocol,
		MimeType:   mimeType,
	}

	result := t.db.WithContext(ctx).Create(upload)

	if result.Error != nil {
		return nil, result.Error
	}

	return upload, nil
}
func (t *TusHandler) UploadProgress(ctx context.Context, uploadID string) error {

	find := &models.TusUpload{UploadID: uploadID}

	var upload models.TusUpload
	result := t.db.Model(&models.TusUpload{}).Where(find).First(&upload)

	if result.RowsAffected == 0 {
		return errors.New("upload not found")
	}

	result = t.db.WithContext(ctx).Model(&models.TusUpload{}).Where(find).Update("updated_at", time.Now())

	if result.Error != nil {
		return result.Error
	}

	return nil
}
func (t *TusHandler) UploadCompleted(ctx context.Context, uploadID string) error {

	find := &models.TusUpload{UploadID: uploadID}

	var upload models.TusUpload
	result := t.db.Model(&models.TusUpload{}).Where(find).First(&upload)

	if result.RowsAffected == 0 {
		return errors.New("upload not found")
	}

	result = t.db.WithContext(ctx).Model(&models.TusUpload{}).Where(find).Update("completed", true)

	if result.Error != nil {
		return result.Error
	}

	return nil
}
func (t *TusHandler) DeleteUpload(ctx context.Context, uploadID string) error {
	result := t.db.WithContext(ctx).Where(&models.TusUpload{UploadID: uploadID}).Delete(&models.TusUpload{})

	if result.Error != nil {
		return result.Error
	}

	return nil
}

func (t *TusHandler) ScheduleUpload(ctx context.Context, uploadID string) error {
	find := &models.TusUpload{UploadID: uploadID}

	var upload models.TusUpload
	result := t.db.WithContext(ctx).Model(&models.TusUpload{}).Where(find).First(&upload)

	if result.RowsAffected == 0 {
		return errors.New("upload not found")
	}

	uploadID = upload.UploadID

	err := t.cron.CreateJob(define.CronTaskTusUploadVerifyName, define.CronTaskTusUploadVerifyArgs{
		Id: uploadID,
	}, []string{uploadID})
	if err != nil {
		return err
	}

	return nil
}

func (t *TusHandler) GetUploadReader(ctx context.Context, hash []byte, start int64) (io.ReadCloser, error) {
	exists, upload := t.UploadHashExists(ctx, hash)

	if !exists {
		return nil, gorm.ErrRecordNotFound
	}

	meta, err := t.tusStore.GetUpload(ctx, upload.UploadID)
	if err != nil {
		return nil, err
	}

	info, err := meta.GetInfo(ctx)
	if err != nil {
		return nil, err
	}

	if start > 0 {
		endPosition := start + info.Size - 1
		rangeHeader := fmt.Sprintf("bytes=%d-%d", start, endPosition)
		ctx = context.WithValue(ctx, CtxRangeKey, rangeHeader)
	}

	reader, err := meta.GetReader(ctx)
	if err != nil {
		return nil, err
	}

	return reader, nil
}

func (t *TusHandler) SetStorageProtocol(storageProtocol core.StorageProtocol) {
	t.storageProtocol = storageProtocol
}

func (t *TusHandler) GetUploadSize(ctx context.Context, hash []byte) (int64, error) {
	exists, upload := t.UploadHashExists(ctx, hash)

	if !exists {
		return 0, gorm.ErrRecordNotFound
	}

	meta, err := t.tusStore.GetUpload(ctx, upload.UploadID)
	if err != nil {
		return 0, err
	}

	info, err := meta.GetInfo(ctx)
	if err != nil {
		return 0, err
	}

	return info.Size, nil
}

func (t *TusHandler) worker() {
	ctx := t.ctx

	// Start a goroutine to handle created uploads
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case info := <-t.tus.CreatedUploads:
				hash, ok := info.Upload.MetaData["hash"]
				errorResponse := handler.HTTPResponse{StatusCode: 400, Header: nil}
				if !ok {
					t.logger.Error("Missing hash in metadata")
					continue
				}

				uploaderID, ok := info.Context.Value(middleware.DEFAULT_USER_ID_CONTEXT_KEY).(uint)
				if !ok {
					errorResponse.Body = "Missing user id in context"
					info.Upload.StopUpload(errorResponse)
					t.logger.Error("Missing user id in context")
					continue
				}

				uploaderIP := info.HTTPRequest.RemoteAddr

				decodedHash, err := encoding.MultihashFromBase64Url(hash)

				if err != nil {
					errorResponse.Body = "Could not decode hash"
					info.Upload.StopUpload(errorResponse)
					t.logger.Error("Could not decode hash", zap.Error(err))
					continue
				}

				var mimeType string

				for _, field := range []string{"mimeType", "mimetype", "filetype"} {
					typ, ok := info.Upload.MetaData[field]
					if ok {
						mimeType = typ
						break
					}
				}

				_, err = t.CreateUpload(ctx, decodedHash.HashBytes(), info.Upload.ID, uploaderID, uploaderIP, t.storageProtocol.Name(), mimeType)
				if err != nil {
					errorResponse.Body = "Could not create tus upload"
					info.Upload.StopUpload(errorResponse)
					t.logger.Error("Could not create tus upload", zap.Error(err))
					continue
				}
			}
		}
	}()

	// Start a goroutine to handle upload progress
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case info := <-t.tus.UploadProgress:
				err := t.UploadProgress(ctx, info.Upload.ID)
				if err != nil {
					t.logger.Error("Could not update tus upload", zap.Error(err))
					continue
				}
			}
		}

	}()

	// Start a goroutine to handle terminated uploads
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case info := <-t.tus.TerminatedUploads:
				err := t.DeleteUpload(ctx, info.Upload.ID)
				if err != nil {
					t.logger.Error("Could not delete tus upload", zap.Error(err))
					continue
				}
			}
		}
	}()

	// Start a goroutine to handle completed uploads
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case info := <-t.tus.CompleteUploads:
				if !(!info.Upload.SizeIsDeferred && info.Upload.Offset == info.Upload.Size) {
					continue
				}

				err := t.UploadCompleted(ctx, info.Upload.ID)
				if err != nil {
					t.logger.Error("Could not complete tus upload", zap.Error(err))
					continue
				}
				err = t.ScheduleUpload(ctx, info.Upload.ID)
				if err != nil {
					t.logger.Error("Could not schedule tus upload", zap.Error(err))
					continue
				}
			}
		}
	}()
}

func getLockerMode(cm config.Manager, logger *core.Logger) string {
	cfg := cm.GetProtocol("s5").(*Config)

	switch cfg.TUSLockerMode {
	case "", "none":
		return "none"
	case "db":
		return "db"
	case "etcd":
		if cm.Config().Core.Clustered.Enabled {
			return "etcd"
		}

		return "db"
	default:
		logger.Fatal("invalid locker mode", zap.String("mode", cfg.TUSLockerMode))
	}

	return "none"
}

func getLocker(cm config.Manager, db *gorm.DB, logger *core.Logger) (handler.Locker, error) {
	mode := getLockerMode(cm, logger)

	switch mode {
	case "none":
		return nil, nil
	case "db":
		return NewDbLocker(db, logger), nil
	case "etcd":
		client, err := cm.Config().Core.Clustered.Etcd.Client()
		if err != nil {
			return nil, err
		}
		locker, err := etcd3locker.NewWithPrefix(client, "s5-tus-locks")
		if err != nil {
			return nil, err
		}
		return locker, nil
	}

	return nil, nil
}
