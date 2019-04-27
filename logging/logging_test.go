package logging

import (
	"testing"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestLogging(t *testing.T) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	RegisterFailHandler(Fail)
	RunSpecs(t, "Logging")
}

var _ = Describe("logging operations", func() {
	BeforeEach(func() {
		loggingStderr = false
		loggingFp = nil
		loggingLevel = PanicLevel
	})
	It("Check file setter with empty", func() {
		SetLogFile("")
		Expect(loggingFp).To(BeNil())
	})
	It("Check file setter with empty", func() {
		SetLogFile("/tmp/foobar.logging")
		Expect(loggingFp).NotTo(Equal(nil))
	})
	It("Check loglevel setter", func() {
		SetLogLevel("debug")
		Expect(loggingLevel).To(Equal(DebugLevel))
		SetLogLevel("Error")
		Expect(loggingLevel).To(Equal(ErrorLevel))
		SetLogLevel("VERbose")
		Expect(loggingLevel).To(Equal(VerboseLevel))
		SetLogLevel("PANIC")
		Expect(loggingLevel).To(Equal(PanicLevel))
	})
	It("Check loglevel setter with invalid level", func() {
		currentLevel := loggingLevel
		SetLogLevel("XXXX")
		Expect(loggingLevel).To(Equal(currentLevel))
	})
	It("Check log to stderr setter with invalid level", func() {
		currentVal := loggingStderr
		SetLogStderr(!currentVal)
		Expect(loggingStderr).NotTo(Equal(currentVal))
	})
})
