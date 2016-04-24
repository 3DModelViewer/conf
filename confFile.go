package conf

type confFile struct {
	Log     logConf     `json:"log"`
	Vada    vadaConf    `json:"vada"`
	Caca    cacaConf    `json:"caca"`
	Sql     sqlConf     `json:"sql"`
	CoreApi coreApiConf `json:"coreApi"`
	Session sessionConf `json:"session"`
	Web     webConf     `json:"web"`
}

type logConf struct {
	Type          string   `json:"type"`          // "console", "devNull", "local"
	PrintToStdOut bool     `json:"printToStdOut"` // true, false
	LineSpacing   int      `json:"lineSpacing"`   // 0, 1
	Dir           []string `json:"dir"`           // ["relative", "file", "path", "segments"]
}

type vadaConf struct {
	Host   string `json:"host"`   //"https://developer.api.autodesk.com"
	Key    string `json:"key"`    // "vzZyhg9MZwhZhptG6JqCeR6gQorM8xvW" //TODO need to add encryption for these at some point
	Secret string `json:"secret"` // "Xc900b546fdb941f" //TODO need to add encryption for these at some point
}

type cacaConf struct {
	Host   string `json:"host"`   //"http://shflinux03:4000"
}

type sqlConf struct {
	MySqlConnection string `json:"mySqlconnection"`
}

type coreApiConf struct {
	SubtaskTimeout  string `json:"subtaskTimeout"` // "5s"
	BatchGetTimeout string `json:"batchGetTimeout"`    // "5s"
	OssBucketPrefix string `json:"ossBucketPrefix"`    // "modelhub_01"
	OssBucketPolicy string `json:"ossBucketPolicy"`    // "transient"/"temporary"/"persistent"
}

type sessionConf struct {
	Name                        string   `json:"name"`                        // "mh"
	MaxAge                      int      `json:"maxAge"`                      // 432000
	KeyPairs                    []string `json:"keyPairs"`                    // ["abcdefghijklmnopqrstuvwxyzabcdef", "abcdefghijklmnopqrstuvwxyzabcdef"]
	MaxRecentSheetCount         int      `json:"maxRecentSheetCount"`         // 25
	RecentSheetAccessExpiration string   `json:"recentSheetAccessExpiration"` // "5m"
}

type webConf struct {
	Host           string   `json:"host"`           // "typhoon.autodesk.com"
	Port           int      `json:"port"`           // 8080, 80
	PublicDir      []string `json:"publicDir"`      // ["relative", "file", "path", "segments"]
	CertFile       []string `json:"certFile"`       // ["relative", "file", "path", "segments"]
	KeyFile        []string `json:"keyFile"`        // ["relative", "file", "path", "segments"]
	CsrfAuthKey    string   `json:csrfAuthKey`      // a hex string representing 32 bytes "56b3ae20971fcee02882e5ec01882611690703a4814e687d9aad4bfc0f9a38c3"
	OpenIdProvider string   `json:"openIdProvider"` // "https://accounts.autodesk.com"
}
