// Package log 提供极简的分级日志。
// 真实 Clash 用 uber/zap + 按日志级别订阅，教学版只用标准库，
// 但保留同样的调用习惯：log.Infoln / log.Warnln。
package log

import (
	"log"
	"os"
)

var (
	// L 是全局 logger。生产环境 Clash 用 zap.SugaredLogger，
	// 这里用标准库 log 顶替，接口一致（都有 Println/Printf）。
	L = log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
)

func Infoln(v ...any)  { L.Println(v...) }
func Warnln(v ...any)  { L.Println(v...) }
func Errorln(v ...any) { L.Println(v...) }
func Infof(f string, v ...any)  { L.Printf(f, v...) }
func Warnf(f string, v ...any)  { L.Printf(f, v...) }
func Errorf(f string, v ...any) { L.Printf(f, v...) }
