package tasks

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/LumeWeb/portal-plugin-s5/internal/cron/define"
	"github.com/LumeWeb/portal-plugin-s5/internal/protocol"
	"github.com/LumeWeb/portal/bao"
	"github.com/LumeWeb/portal/core"
	"github.com/LumeWeb/portal/db/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/tus/tusd/v2/pkg/handler"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"io"
	"strings"
	"time"
)

func getReader(ctx context.Context, upload handler.Upload) (io.ReadCloser, error) {
	muReader, err := upload.GetReader(ctx)
	if err != nil {
		return nil, err
	}
	return muReader, nil
}

func closeReader(reader io.ReadCloser, ctx core.Context) {
	err := reader.Close()
	if err != nil {
		ctx.Logger().Error("error closing reader", zap.Error(err))
	}
}

func cronTaskTusGetUpload(ctx core.Context, id string) (*models.TusUpload, handler.Upload, *handler.FileInfo, error) {
	proto, err := core.GetProtocol("s5")
	if err != nil {
		return nil, nil, nil, err
	}

	tus := proto.(*protocol.S5Protocol).TusHandler()

	exists, upload := tus.UploadExists(ctx, id)

	logger := ctx.Logger()

	if !exists {
		logger.Error("Upload not found", zap.String("hash", hex.EncodeToString(upload.Hash)))
		return nil, nil, nil, gorm.ErrRecordNotFound
	}

	tusUpload, err := tus.TusStore().GetUpload(ctx, upload.UploadID)
	if err != nil {
		logger.Error("Could not get upload", zap.Error(err))
		return nil, nil, nil, err
	}

	info, err := tusUpload.GetInfo(ctx)
	if err != nil {
		logger.Error("Could not get tus info", zap.Error(err))
		return nil, nil, nil, err
	}

	return &upload, tusUpload, &info, nil
}

func CronTaskTusUploadVerify(input any, ctx core.Context) error {
	args, ok := input.(*define.CronTaskTusUploadVerifyArgs)
	if !ok {
		return errors.New("invalid arguments type")
	}

	logger := ctx.Logger()
	storage := ctx.Services().Storage()
	crn := ctx.Services().Cron()

	upload, tusUpload, info, err := cronTaskTusGetUpload(ctx, args.Id)
	if err != nil {
		return err
	}

	reader, err := getReader(ctx, tusUpload)
	if err != nil {
		logger.Error("Could not get tus file", zap.Error(err))
		return err
	}

	defer closeReader(reader, ctx)

	proof, err := storage.HashObject(ctx, reader, uint64(info.Size))

	if err != nil {
		logger.Error("Could not compute proof", zap.Error(err))
		return err
	}

	if !bytes.Equal(proof.Hash, upload.Hash) {
		logger.Error("Hashes do not match", zap.Any("upload", upload), zap.Any("dbHash", hex.EncodeToString(upload.Hash)))
		return err
	}

	err = crn.CreateJob(define.CronTaskTusUploadProcessName, define.CronTaskTusUploadProcessArgs{
		Id:    args.Id,
		Proof: proof.Proof,
	}, []string{upload.UploadID})
	if err != nil {
		return err
	}

	return nil
}

func CronTaskTusUploadProcess(input any, ctx core.Context) error {
	args, ok := input.(*define.CronTaskTusUploadProcessArgs)
	if !ok {
		return errors.New("invalid arguments type")
	}

	upload, tusUpload, info, err := cronTaskTusGetUpload(ctx, args.Id)
	if err != nil {
		return err
	}

	pin := ctx.Services().Pin()
	storage := ctx.Services().Storage()
	logger := ctx.Logger()
	metadata := ctx.Services().Metadata()
	crn := ctx.Services().Cron()
	proto, err := core.GetProtocol("s5")
	if err != nil {
		return err
	}

	tus := proto.(*protocol.S5Protocol)

	var uploadMeta core.UploadMetadata

	doUpload := true

	pinned, err := pin.UploadPinnedByUser(upload.Hash, upload.UploaderID)
	if err != nil {
		return err
	}

	if !pinned {
		status, err := storage.UploadStatus(ctx, tus.StorageProtocol(), tus.StorageProtocol().EncodeFileName(upload.Hash))
		if err != nil {
			return err
		}

		if status == core.StorageUploadStatusActive {
			doUpload = false

			err = waitForUploadCompletion(ctx, upload.Hash)
			if err != nil {
				return err
			}
		}
	} else {
		doUpload = false
	}

	if doUpload {
		meta, err := storage.UploadObject(ctx, tus.StorageProtocol(), nil, 0, &core.MultiPartUploadParams{
			ReaderFactory: func(start uint, end uint) (io.ReadCloser, error) {
				rangeHeader := "bytes=%d-"
				if end != 0 {
					rangeHeader += "%d"
					rangeHeader = fmt.Sprintf(rangeHeader, start, end)
				} else {
					rangeHeader = fmt.Sprintf("bytes=%d-", start)
				}
				return tusUpload.GetReader(context.WithValue(ctx, protocol.CtxRangeKey, rangeHeader))
			},
			Bucket:   upload.Protocol,
			FileName: tus.StorageProtocol().EncodeFileName(upload.Hash),
			Size:     uint64(info.Size),
		}, &bao.Result{
			Hash:   upload.Hash,
			Proof:  args.Proof,
			Length: uint(info.Size),
		})

		if err != nil {
			logger.Error("Could not upload file", zap.Error(err))
			return err
		}

		uploadMeta = *meta
	} else {
		meta, err := metadata.GetUpload(ctx, upload.Hash)
		if err != nil {
			return err
		}

		uploadMeta = meta
	}

	err = crn.CreateJob(define.CronTaskTusUploadCleanupName, define.CronTaskTusUploadCleanupArgs{
		Protocol: uploadMeta.Protocol,
		Id:       args.Id,
		MimeType: uploadMeta.MimeType,
		Size:     uploadMeta.Size,
	}, []string{upload.UploadID})
	if err != nil {
		return err
	}

	return nil
}

func CronTaskTusUploadCleanup(input any, ctx core.Context) error {
	args, ok := input.(*define.CronTaskTusUploadCleanupArgs)
	if !ok {
		return errors.New("invalid arguments type")
	}

	upload, _, _, err := cronTaskTusGetUpload(ctx, args.Id)
	if err != nil {
		return err
	}

	proto, err := core.GetProtocol("s5")
	if err != nil {
		return err
	}

	tus := proto.(*protocol.S5Protocol).TusHandler()
	config := ctx.Config()
	logger := ctx.Logger()
	metadata := ctx.Services().Metadata()
	pin := ctx.Services().Pin()

	s3InfoId, _ := splitS3Ids(upload.UploadID)

	_, err = tus.S3Client().DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: aws.String(config.Config().Core.Storage.S3.BufferBucket),
		Delete: &s3types.Delete{
			Objects: []s3types.ObjectIdentifier{
				{
					Key: aws.String(s3InfoId),
				},
				{
					Key: aws.String(s3InfoId + ".info"),
				},
			},
			Quiet: aws.Bool(true),
		},
	})

	if err != nil {
		logger.Error("Could not delete upload metadata", zap.Error(err))
		return err
	}

	uploadMeta := core.UploadMetadata{
		Hash:     upload.Hash,
		MimeType: args.MimeType,
		Protocol: args.Protocol,
		Size:     args.Size,
	}

	uploadMeta.UserID = upload.UploaderID
	uploadMeta.UploaderIP = upload.UploaderIP

	err = metadata.SaveUpload(ctx, uploadMeta, true)
	if err != nil {
		logger.Error("Could not create upload", zap.Error(err))
		return err
	}

	err = pin.PinByHash(upload.Hash, upload.UploaderID)
	if err != nil {
		logger.Error("Could not pin upload", zap.Error(err))
		return err
	}

	err = tus.DeleteUpload(ctx, upload.UploadID)
	if err != nil {
		logger.Error("Error deleting tus upload", zap.Error(err))
		return err
	}

	return nil
}
func waitForUploadCompletion(ctx core.Context, hash []byte) error {
	proto, err := core.GetProtocol("s5")
	if err != nil {
		return err
	}

	tus := proto.(*protocol.S5Protocol)
	storage := ctx.Services().Storage()

	for {
		status, err := storage.UploadStatus(ctx, tus.StorageProtocol(), tus.StorageProtocol().EncodeFileName(hash))
		if err != nil {
			return err
		}
		if status != core.StorageUploadStatusActive {
			break
		}
		time.Sleep(5 * time.Second)
	}
	return nil
}

func splitS3Ids(id string) (objectId, multipartId string) {
	index := strings.Index(id, "+")
	if index == -1 {
		return
	}

	objectId = id[:index]
	multipartId = id[index+1:]
	return
}
