package tasks

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/ddo/rq"
	"go.lumeweb.com/libs5-go/encoding"
	"go.lumeweb.com/portal-plugin-s5/internal/cron/define"
	"go.lumeweb.com/portal-plugin-s5/internal/protocol"
	syncTypes "go.lumeweb.com/portal-plugin-sync/types"
	"go.lumeweb.com/portal/bao"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db/models"
	"go.uber.org/zap"
	"io"
	"net/http"
)

const totalPinImportStages = 3

func pinImportCloseBody(body io.ReadCloser, ctx core.Context) {
	if err := body.Close(); err != nil {
		ctx.Logger().Error("error closing response body", zap.Error(err))
	}
}

func pinImportFetchAndProcess(fetchUrl string, progressStage int, ctx core.Context, cid *encoding.CID) ([]byte, error) {
	logger := ctx.Logger()
	_import := ctx.Service(core.IMPORT_SERVICE).(core.ImportService)
	req, err := rq.Get(fetchUrl).ParseRequest()
	if err != nil {
		logger.Error("error parsing request", zap.Error(err))
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Error("error executing request", zap.Error(err))
		return nil, err
	}

	defer pinImportCloseBody(res.Body, ctx)

	if res.StatusCode != http.StatusOK {
		errMsg := "error fetching URL: " + fetchUrl
		logger.Error(errMsg, zap.String("status", res.Status))
		return nil, fmt.Errorf(errMsg+" with status: %s", res.Status)
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		logger.Error("error reading response body", zap.Error(err))
		return nil, err
	}

	err = _import.UpdateProgress(ctx, cid.Hash.HashBytes(), progressStage, totalPinImportStages)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func pinImportSaveAndPin(upload *core.UploadMetadata, ctx core.Context, cid *encoding.CID, userId uint) error {
	_import := ctx.Service(core.IMPORT_SERVICE).(core.ImportService)
	metadata := ctx.Service(core.METADATA_SERVICE).(core.MetadataService)
	pin := ctx.Service(core.PIN_SERVICE).(core.PinService)

	err := _import.UpdateProgress(ctx, cid.Hash.HashBytes(), 3, totalPinImportStages)
	if err != nil {
		return err
	}

	upload.UserID = userId
	if err := metadata.SaveUpload(ctx, *upload, true); err != nil {
		return err
	}

	if err := pin.PinByHash(upload.Hash, userId); err != nil {
		return err
	}

	err = _import.DeleteImport(ctx, upload.Hash)
	if err != nil {
		return err
	}

	return nil
}

func CronTaskPinImportValidate(input any, ctx core.Context) error {
	args, ok := input.(*define.CronTaskPinImportValidateArgs)
	if !ok {
		return errors.New("invalid arguments type")
	}

	config := ctx.Config()
	logger := ctx.Logger()
	_import := ctx.Service(core.IMPORT_SERVICE).(core.ImportService)
	crn := ctx.Service(core.CRON_SERVICE).(core.CronService)

	// Parse CID early to avoid unnecessary operations if it fails.
	parsedCid, err := encoding.CIDFromString(args.Cid)
	if err != nil {
		logger.Error("error parsing cid", zap.Error(err))
		return err
	}

	err = _import.UpdateStatus(ctx, parsedCid.Hash.HashBytes(), models.ImportStatusProcessing)
	if err != nil {
		return err
	}

	if parsedCid.Size <= config.Config().Core.PostUploadLimit {
		err = crn.CreateJobIfNotExists(define.CronTaskPinImportProcessSmallFileName, define.CronTaskPinImportProcessSmallFileArgs{
			Cid:      args.Cid,
			Url:      args.Url,
			ProofUrl: args.ProofUrl,
			UserId:   args.UserId,
		}, []string{args.Cid})
		if err != nil {
			return err
		}
	}

	err = crn.CreateJobIfNotExists(define.CronTaskPinImportProcessLargeFileName, define.CronTaskPinImportProcessLargeFileArgs{
		Cid:      args.Cid,
		Url:      args.Url,
		ProofUrl: args.ProofUrl,
		UserId:   args.UserId,
	}, []string{args.Cid})
	if err != nil {
		return err
	}

	return nil
}

func CronTaskPinImportProcessSmallFile(input any, ctx core.Context) error {
	args, ok := input.(*define.CronTaskPinImportProcessSmallFileArgs)
	if !ok {
		return errors.New("invalid arguments type")
	}

	logger := ctx.Logger()
	storage := ctx.Service(core.STORAGE_SERVICE).(core.StorageService)
	_import := ctx.Service(core.IMPORT_SERVICE).(core.ImportService)
	sync := ctx.Service(syncTypes.SYNC_SERVICE).(syncTypes.SyncService)

	parsedCid, err := encoding.CIDFromString(args.Cid)
	if err != nil {
		logger.Error("error parsing cid", zap.Error(err))
		return err
	}

	fileData, err := pinImportFetchAndProcess(args.Url, 1, ctx, parsedCid)
	if err != nil {
		return err // Error logged in fetchAndProcess
	}

	hash, err := storage.HashObject(ctx, bytes.NewReader(fileData), uint64(len(fileData)))
	if err != nil {
		logger.Error("error hashing object", zap.Error(err))
		return err
	}

	if !bytes.Equal(hash.Hash, parsedCid.Hash.HashBytes()) {
		return fmt.Errorf("hash mismatch")
	}

	err = _import.UpdateProgress(ctx, parsedCid.Hash.HashBytes(), 2, totalPinImportStages)
	if err != nil {
		return err
	}

	proto := core.GetProtocol("s5")

	if proto == nil {
		return errors.New("protocol not found")
	}

	upload, err := storage.UploadObject(ctx, protocol.GetStorageProtocol(proto), bytes.NewReader(fileData), parsedCid.Size, nil, hash)
	if err != nil {
		return err
	}

	err = pinImportSaveAndPin(upload, ctx, parsedCid, args.UserId)
	if err != nil {
		return err
	}

	err = sync.Update(*upload)

	if err != nil {
		return err
	}

	return nil
}

func CronTaskPinImportProcessLargeFile(input any, ctx core.Context) error {
	args, ok := input.(*define.CronTaskPinImportProcessLargeFileArgs)
	if !ok {
		return errors.New("invalid arguments type")
	}

	config := ctx.Config()
	logger := ctx.Logger()
	storage := ctx.Service(core.STORAGE_SERVICE).(core.StorageService)
	_import := ctx.Service(core.IMPORT_SERVICE).(core.ImportService)
	sync := ctx.Service(syncTypes.SYNC_SERVICE).(syncTypes.SyncService)

	parsedCid, err := encoding.CIDFromString(args.Cid)
	if err != nil {
		logger.Error("error parsing cid", zap.Error(err))
		return err
	}

	// Fetch proof.
	proof, err := pinImportFetchAndProcess(args.ProofUrl, 1, ctx, parsedCid)
	if err != nil {
		return err
	}

	baoProof := bao.Result{
		Hash:   parsedCid.Hash.HashBytes(),
		Proof:  proof,
		Length: uint(parsedCid.Size),
	}

	client, err := storage.S3Client(ctx)
	if err != nil {
		logger.Error("error getting s3 client", zap.Error(err))
		return err
	}

	req, err := rq.Get(args.Url).ParseRequest()
	if err != nil {
		logger.Error("error parsing request", zap.Error(err))
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Error("error executing request", zap.Error(err))
		return err
	}
	defer pinImportCloseBody(res.Body, ctx)

	verifier := bao.NewVerifier(res.Body, baoProof, logger.Logger)
	defer pinImportCloseBody(verifier, ctx)

	if parsedCid.Size < core.S3_MULTIPART_MIN_PART_SIZE {
		_, err = client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:        aws.String(config.Config().Core.Storage.S3.BufferBucket),
			Key:           aws.String(args.Cid),
			Body:          verifier,
			ContentLength: aws.Int64(int64(parsedCid.Size)),
		})
		if err != nil {
			logger.Error("error uploading object", zap.Error(err))
			return err
		}
	} else {
		err := storage.S3MultipartUpload(ctx, verifier, config.Config().Core.Storage.S3.BufferBucket, args.Cid, parsedCid.Size)
		if err != nil {
			logger.Error("error uploading object", zap.Error(err))
			return err
		}
	}

	err = _import.UpdateProgress(ctx, parsedCid.Hash.HashBytes(), 2, totalPinImportStages)
	if err != nil {
		return err
	}

	proto := core.GetProtocol("s5")

	if proto == nil {
		return errors.New("protocol not found")
	}

	storageProtocol := protocol.GetStorageProtocol(proto)

	upload, err := storage.UploadObject(ctx, storageProtocol, nil, 0, &core.MultiPartUploadParams{
		ReaderFactory: func(start uint, end uint) (io.ReadCloser, error) {
			rangeHeader := "bytes=%d-"
			if end != 0 {
				rangeHeader += "%d"
				rangeHeader = fmt.Sprintf("bytes=%d-%d", start, end)
			} else {
				rangeHeader = fmt.Sprintf("bytes=%d-", start)
			}
			object, err := client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(config.Config().Core.Storage.S3.BufferBucket),
				Key:    aws.String(args.Cid),
				Range:  aws.String(rangeHeader),
			})

			if err != nil {
				return nil, err
			}

			return object.Body, nil
		},
		Bucket:          config.Config().Core.Storage.S3.BufferBucket,
		FileName:        storageProtocol.EncodeFileName(parsedCid.Hash.HashBytes()),
		Size:            parsedCid.Size,
		UploadIDHandler: nil,
	}, &baoProof)

	if err != nil {
		logger.Error("error uploading object", zap.Error(err))
		return err
	}

	err = pinImportSaveAndPin(upload, ctx, parsedCid, args.UserId)
	if err != nil {
		return err
	}

	err = sync.Update(*upload)

	if err != nil {
		return err
	}

	return nil
}
