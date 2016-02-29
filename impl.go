package conf

import (
	"os"
	"path/filepath"
	"net/http"
	"github.com/robsix/golog"
	"io/ioutil"
	"encoding/json"
	"errors"
	v "github.com/modelhub/vada"
	"github.com/modelhub/core"
	"github.com/modelhub/wall"
	"database/sql"
	"github.com/modelhub/session"
	"strconv"
	"time"
	"github.com/modelhub/rest"
)

var(
	wd, _ = os.Getwd()
	fpj = filepath.Join
)

func GetAppConf() *conf {
	log := golog.NewConsoleLog(0)
	confFile := readConfFile(log)
	log = createLog(confFile, log)
	vada := createVadaClient(confFile, log)
	coreApi := createCoreApi(confFile, vada, log)
	sessionGetter := createSessionGetter(confFile, log)
	restApi := createRestApi(coreApi, sessionGetter, vada, log)
	fullUrlBase := createFullUrlBase(confFile)
	wall := createWall(confFile, coreApi, restApi, sessionGetter, fullUrlBase, vada, log)
	portString := createPortString(confFile)
	certFile := createCertFilePath(confFile)
	keyFile := createKeyFilePath(confFile)

	return &conf{
		RootMux: 	wall,
		FullUrlBase:    	fullUrlBase,
		portString:         portString,
		certFile:       	certFile,
		keyFile:        	keyFile,
		log:            	log,
	}
}

func readConfFile(log golog.Log) *confFile {
	confFileBytes, err := ioutil.ReadFile(fpj(wd, "conf.json"))
	if err != nil {
		log.Critical("Failed to read conf file: %v", err)
		panic(err)
	}

	confFile := &confFile{}
	err = json.Unmarshal(confFileBytes, confFile)
	if err != nil {
		log.Critical("Failed to unmarshal conf file json: %v", err)
		panic(err)
	}

	log.Info("conf.json: %v", confFile)
	return confFile
}

func createLog(confFile *confFile, log golog.Log) golog.Log {
	var logInst golog.Log
	var err error
	switch confFile.Log.Type {
	case "devNull":
		logInst = golog.NewDevNullLog()
	case "console":
		logInst = golog.NewConsoleLog(confFile.Log.LineSpacing)
	case "local":
		logInst, err = golog.NewLocalLog(fpj(wd, fpj(confFile.Log.Dir...)), confFile.Log.PrintToStdOut, confFile.Log.LineSpacing)
		if err != nil {
			log.Critical("Failed to create local log: %v", err)
			panic(err)
		}
	default:
		err = errors.New("Unknown log type: " + confFile.Log.Type)
		log.Critical("Failed to create log: %v", err)
		panic(err)
	}
	return logInst
}

func createVadaClient(confFile *confFile, log golog.Log) v.VadaClient {
	return v.NewVadaClient(confFile.Vada.Host, confFile.Vada.Key, confFile.Vada.Secret, log)
}

func createCoreApi(confFile *confFile, vada v.VadaClient, log golog.Log) core.CoreApi {
	var bucketPolicy v.BucketPolicy
	switch confFile.CoreApi.OssBucketPolicy {
	case "transient":
		bucketPolicy = v.Transient
	case "temporary":
		bucketPolicy = v.Temporary
	case "persistent":
		bucketPolicy = v.Persistent
	default:
		err := errors.New("Unknown bucket policy type: " + confFile.CoreApi.OssBucketPolicy)
		log.Critical("Failed to create CoreApi: %v", err)
		panic(err)
	}
	if db, err := sql.Open(confFile.Sql.Driver, confFile.Sql.Connection); err != nil {
		log.Critical("Failed to create CoreApi: %v", err)
		panic(err)
	} else if dur, err := time.ParseDuration(confFile.CoreApi.StatusCheckTimeout); err != nil {
		log.Critical("Failed to create CoreApi: %v", err)
		panic(err)
	} else {
		return core.NewSqlCoreApi(db, vada, dur, confFile.CoreApi.OssBucketPrefix, bucketPolicy, log)
	}
}

func createSessionGetter(confFile *confFile, log golog.Log) session.SessionGetter {
	if len(confFile.Session.SessionKeyPairs) == 0 || len(confFile.Session.SessionKeyPairs) % 2 != 0 {
		err := errors.New("StormConf WebConf len(SessionKeyPairs) must be a POSITIVE EVEN integer")
		log.Critical(err)
		panic(err)
	}
	sessionKeyPairs := make([][]byte, 0, len(confFile.Session.SessionKeyPairs))
	for _, str := range confFile.Session.SessionKeyPairs {
		bytes := []byte(str)
		if len(bytes) != 32 {
			err := errors.New("StormConf WebConf len(SessionKey) must be 32")
			log.Critical(err)
			panic(err)
		}
		sessionKeyPairs = append(sessionKeyPairs, []byte(str))
	}
	if dur, err := time.ParseDuration(confFile.Session.RecentSheetAccessExpiration); err != nil {
		log.Critical("Failed to create SessionGetter: %v", err)
		panic(err)
	} else {
		return session.NewCookieSessionGetter(sessionKeyPairs, confFile.Session.SessionMaxAge, confFile.Session.SessionName, confFile.Session.MaxRecentSheetCount, dur)
	}

}

func createRestApi(coreApi core.CoreApi, sessionGetter session.SessionGetter, vada v.VadaClient, log golog.Log) *http.ServeMux {
	return rest.NewRestApi(coreApi, sessionGetter, vada, log)
}

func createWall(confFile *confFile, coreApi core.CoreApi, restApi *http.ServeMux, sessionGetter session.SessionGetter, fullUrlBase string, vada v.VadaClient, log golog.Log) *http.ServeMux {
	return wall.NewWall(coreApi, restApi, sessionGetter, confFile.Web.OpenIdProvider, fullUrlBase, fpj(wd, fpj(confFile.Web.PublicDir...)))
}

func createCertFilePath(confFile *confFile) string {
	certFile := ""
	if len(confFile.Web.CertFile) > 0 {
		certFile = fpj(wd, fpj(confFile.Web.CertFile...))
	}
	return certFile
}

func createKeyFilePath(confFile *confFile) string {
	keyFile := ""
	if len(confFile.Web.CertFile) > 0 {
		keyFile = fpj(wd, fpj(confFile.Web.KeyFile...))
	}
	return keyFile
}

func createPortString(confFile *confFile) string {
	return ":" + strconv.Itoa(confFile.Web.Port)
}

func createFullUrlBase(confFile *confFile) string {
	scheme := "http://"
	if len(confFile.Web.CertFile) != 0 && len(confFile.Web.KeyFile) != 0 {
		scheme = "https://"
	}

	portStr := ""
	if confFile.Web.Port != 80 {
		portStr = ":" + strconv.Itoa(confFile.Web.Port)
	}

	return scheme + confFile.Web.Host + portStr
}

type conf struct {
	RootMux			  *http.ServeMux
	FullUrlBase		  string
	PortString		  string
	CertFile          string
	KeyFile           string
}