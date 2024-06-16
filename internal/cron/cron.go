package cron

import (
	"go.lumeweb.com/portal-plugin-s5/internal/cron/define"
	"go.lumeweb.com/portal-plugin-s5/internal/cron/tasks"
	"go.lumeweb.com/portal/core"
)

var _ core.CronableService = (*Cron)(nil)

type Cron struct {
	ctx core.Context
}

func (c Cron) RegisterTasks(crn core.CronService) error {
	// Import
	crn.RegisterTask(define.CronTaskPinImportValidateName, tasks.CronTaskPinImportValidate, core.CronTaskDefinitionOneTimeJob, define.CronTaskPinImportValidateArgsFactory)
	crn.RegisterTask(define.CronTaskPinImportProcessSmallFileName, tasks.CronTaskPinImportProcessSmallFile, core.CronTaskDefinitionOneTimeJob, define.CronTaskPinImportProcessSmallFileArgsFactory)
	crn.RegisterTask(define.CronTaskPinImportProcessLargeFileName, tasks.CronTaskPinImportProcessLargeFile, core.CronTaskDefinitionOneTimeJob, define.CronTaskPinImportProcessLargeFileArgsFactory)

	// TUS
	crn.RegisterTask(define.CronTaskTusUploadVerifyName, tasks.CronTaskTusUploadVerify, core.CronTaskDefinitionOneTimeJob, define.CronTaskTusUploadVerifyArgsFactory)
	crn.RegisterTask(define.CronTaskTusUploadProcessName, tasks.CronTaskTusUploadProcess, core.CronTaskDefinitionOneTimeJob, define.CronTaskTusUploadProcessArgsFactory)
	crn.RegisterTask(define.CronTaskTusUploadCleanupName, tasks.CronTaskTusUploadCleanup, core.CronTaskDefinitionOneTimeJob, define.CronTaskTusUploadCleanupArgsFactory)
	return nil
}

func (c Cron) ScheduleJobs(_ core.CronService) error {
	return nil
}

func NewCron(ctx core.Context) *Cron {
	return &Cron{ctx: ctx}
}
