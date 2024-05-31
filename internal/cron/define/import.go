package define

const CronTaskPinImportValidateName = "PinImportValidate"

type CronTaskPinImportValidateArgs struct {
	Cid      string
	Url      string
	ProofUrl string
	UserId   uint
}

func CronTaskPinImportValidateArgsFactory() any {
	return &CronTaskPinImportValidateArgs{}
}

const CronTaskPinImportProcessSmallFileName = "PinImportVerify"

type CronTaskPinImportProcessSmallFileArgs struct {
	Cid      string
	Url      string
	ProofUrl string
	UserId   uint
}

func CronTaskPinImportProcessSmallFileArgsFactory() any {
	return &CronTaskPinImportProcessSmallFileArgs{}
}

const CronTaskPinImportProcessLargeFileName = "PinImportProcessLarge"

type CronTaskPinImportProcessLargeFileArgs struct {
	Cid      string
	Url      string
	ProofUrl string
	UserId   uint
}

func CronTaskPinImportProcessLargeFileArgsFactory() any {
	return &CronTaskPinImportProcessLargeFileArgs{}
}
