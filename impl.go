package conf

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/modelhub/core"
	"github.com/modelhub/rest"
	"github.com/modelhub/session"
	v "github.com/modelhub/vada"
	"github.com/modelhub/wall"
	"github.com/robsix/golog"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"github.com/modelhub/caca"
)

var (
	wd, _ = os.Getwd()
	fpj   = filepath.Join
)

func GetAppConf() *conf {
	log := golog.NewConsoleLog(0)
	confFile := readConfFile(log)
	log = createLog(confFile, log)
	vada := createVadaClient(confFile, log)
	caca := createCacaClient(confFile, log)
	coreApi := createCoreApi(confFile, vada, caca, log)
	sessionGetter := createSessionGetter(confFile, log)
	restApi := createRestApi(confFile, coreApi, sessionGetter, vada, log)
	fullUrlBase := createFullUrlBase(confFile)
	wall := createWall(confFile, coreApi, restApi, sessionGetter, fullUrlBase, vada, log)
	portString := createPortString(confFile)
	certFile := createCertFilePath(confFile)
	keyFile := createKeyFilePath(confFile)

	return &conf{
		Wall:        wall,
		Log:         log,
		FullUrlBase: fullUrlBase,
		PortString:  portString,
		CertFile:    certFile,
		KeyFile:     keyFile,
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

	log.Info("conf.json: %#v", confFile)
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

func createCacaClient(confFile *confFile, log golog.Log) caca.CacaClient {
	return caca.NewCacaClient(confFile.Caca.Host, log)
}

func createCoreApi(confFile *confFile, vada v.VadaClient, caca caca.CacaClient, log golog.Log) core.CoreApi {
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
	if subtaskTimeoutDur, err := time.ParseDuration(confFile.CoreApi.SubtaskTimeout); err != nil {
		log.Critical("Failed to create CoreApi: %v", err)
		panic(err)
	} else if batchGetTimeoutDur, err := time.ParseDuration(confFile.CoreApi.BatchGetTimeout); err != nil {
		log.Critical("Failed to create CoreApi: %v", err)
		panic(err)
	} else if coreApi, err := core.NewSqlCoreApi(confFile.Sql.MySqlConnection, vada, caca, subtaskTimeoutDur, batchGetTimeoutDur, confFile.CoreApi.OssBucketPrefix, bucketPolicy, log); err != nil {
		log.Critical("Failed to create CoreApi: %v", err)
		panic(err)
	} else {
		return coreApi
	}
}

func createSessionGetter(confFile *confFile, log golog.Log) session.SessionGetter {
	if len(confFile.Session.KeyPairs) == 0 || len(confFile.Session.KeyPairs)%2 != 0 {
		err := errors.New("StormConf WebConf len(SessionKeyPairs) must be a POSITIVE EVEN integer")
		log.Critical("Failed to create sessionGetter: %v", err)
		panic(err)
	}
	sessionKeyPairs := make([][]byte, 0, len(confFile.Session.KeyPairs))
	for _, str := range confFile.Session.KeyPairs {
		if bytes, err := hex.DecodeString(str); err != nil {
			log.Critical("Failed to create sessionGetter: %v", err)
			panic(err)
		} else {
			if len(bytes) != 32 {
				err := errors.New("StormConf WebConf len(SessionKey) must be 32")
				log.Critical("Failed to create sessionGetter: %v", err)
				panic(err)
			}
			sessionKeyPairs = append(sessionKeyPairs, bytes)
		}
	}
	if dur, err := time.ParseDuration(confFile.Session.RecentSheetAccessExpiration); err != nil {
		log.Critical("Failed to create SessionGetter: %v", err)
		panic(err)
	} else {
		return session.NewCookieSessionGetter(sessionKeyPairs, confFile.Session.MaxAge, confFile.Session.Name, confFile.Session.MaxRecentSheetCount, dur)
	}

}

func createRestApi(confFile *confFile, coreApi core.CoreApi, sessionGetter session.SessionGetter, vada v.VadaClient, log golog.Log) *http.ServeMux {
	return rest.NewRestApi(coreApi, sessionGetter, vada, log)
}

func createWall(confFile *confFile, coreApi core.CoreApi, restApi *http.ServeMux, sessionGetter session.SessionGetter, fullUrlBase string, vada v.VadaClient, log golog.Log) http.Handler {
	if csrfAuthKey, err := hex.DecodeString(confFile.Web.CsrfAuthKey); err != nil {
		log.Critical("Failed to create wall: %v", err)
		panic(err)
	} else if len(csrfAuthKey) != 32 {
		err := errors.New("StormConf WebConf len(CsrfAuthKey) must be 32")
		log.Critical("Failed to create wall: %v", err)
		panic(err)
	} else {
		isOverSecureConnection := false
		if len(confFile.Web.CertFile) != 0 && len(confFile.Web.KeyFile) != 0 {
			isOverSecureConnection = true
		}
		if wall, err := wall.NewWall(coreApi, restApi, sessionGetter, confFile.Web.OpenIdProvider, fullUrlBase, csrfAuthKey, confFile.Session.MaxAge, isOverSecureConnection, fpj(wd, fpj(confFile.Web.PublicDir...))); err != nil {
			log.Critical("Failed to create wall: %v", err)
			panic(err)
		} else {
			return wall
		}
	}
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
	Wall        http.Handler
	Log         golog.Log
	FullUrlBase string
	PortString  string
	CertFile    string
	KeyFile     string
}
