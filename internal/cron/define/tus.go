package define

const CronTaskTusUploadVerifyName = "TUSUploadVerify"
const CronTaskTusUploadProcessName = "TUSUploadProcess"
const CronTaskTusUploadCleanupName = "TUSUploadCleanup"

type CronTaskTusUploadVerifyArgs struct {
	Id string `json:"id"`
}

func CronTaskTusUploadVerifyArgsFactory() any {
	return &CronTaskTusUploadVerifyArgs{}
}

type CronTaskTusUploadProcessArgs struct {
	Id    string `json:"id"`
	Proof []byte `json:"proof"`
}

func CronTaskTusUploadProcessArgsFactory() any {
	return &CronTaskTusUploadProcessArgs{}
}

type CronTaskTusUploadCleanupArgs struct {
	Id       string `json:"id"`
	Protocol string `json:"protocol"`
	MimeType string `json:"mimeType"`
	Size     uint64 `json:"size"`
}

func CronTaskTusUploadCleanupArgsFactory() any {
	return &CronTaskTusUploadCleanupArgs{}
}
