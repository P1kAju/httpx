package runner

import (
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goconfig"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/common/customheader"
	"github.com/projectdiscovery/httpx/common/customlist"
	customport "github.com/projectdiscovery/httpx/common/customports"
	fileutilz "github.com/projectdiscovery/httpx/common/fileutil"
	"github.com/projectdiscovery/httpx/common/slice"
	"github.com/projectdiscovery/httpx/common/stringz"
	"math"
	"os"
	"regexp"
	"strings"
)

const (
	// The maximum file length is 251 (255 - 4 bytes for ".ext" suffix)
	maxFileNameLength      = 251
	two                    = 2
	DefaultResumeFile      = "resume.cfg"
	DefaultOutputDirectory = "output"
)

type scanOptions struct {
	Methods                   []string
	StoreResponseDirectory    string
	RequestURI                string
	RequestBody               string
	VHost                     bool
	OutputTitle               bool
	OutputStatusCode          bool
	OutputLocation            bool
	OutputContentLength       bool
	StoreResponse             bool
	OutputServerHeader        bool
	OutputWebSocket           bool
	OutputWithNoColor         bool
	OutputMethod              bool
	ResponseInStdout          bool
	ChainInStdout             bool
	TLSProbe                  bool
	CSPProbe                  bool
	VHostInput                bool
	OutputContentType         bool
	Unsafe                    bool
	Pipeline                  bool
	HTTP2Probe                bool
	OutputIP                  bool
	OutputCName               bool
	OutputCDN                 bool
	OutputResponseTime        bool
	PreferHTTPS               bool
	NoFallback                bool
	NoFallbackScheme          bool
	TechDetect                bool
	StoreChain                bool
	MaxResponseBodySizeToSave int
	MaxResponseBodySizeToRead int
	OutputExtractRegex        string
	extractRegex              *regexp.Regexp
	ExcludeCDN                bool
	HostMaxErrors             int
	ProbeAllIPS               bool
	Favicon                   bool
	LeaveDefaultPorts         bool
	OutputLinesCount          bool
	OutputWordsCount          bool
	Hashes                    string
}

func (s *scanOptions) Clone() *scanOptions {
	return &scanOptions{
		Methods:                   s.Methods,
		StoreResponseDirectory:    s.StoreResponseDirectory,
		RequestURI:                s.RequestURI,
		RequestBody:               s.RequestBody,
		VHost:                     s.VHost,
		OutputTitle:               s.OutputTitle,
		OutputStatusCode:          s.OutputStatusCode,
		OutputLocation:            s.OutputLocation,
		OutputContentLength:       s.OutputContentLength,
		StoreResponse:             s.StoreResponse,
		OutputServerHeader:        s.OutputServerHeader,
		OutputWebSocket:           s.OutputWebSocket,
		OutputWithNoColor:         s.OutputWithNoColor,
		OutputMethod:              s.OutputMethod,
		ResponseInStdout:          s.ResponseInStdout,
		ChainInStdout:             s.ChainInStdout,
		TLSProbe:                  s.TLSProbe,
		CSPProbe:                  s.CSPProbe,
		OutputContentType:         s.OutputContentType,
		Unsafe:                    s.Unsafe,
		Pipeline:                  s.Pipeline,
		HTTP2Probe:                s.HTTP2Probe,
		OutputIP:                  s.OutputIP,
		OutputCName:               s.OutputCName,
		OutputCDN:                 s.OutputCDN,
		OutputResponseTime:        s.OutputResponseTime,
		PreferHTTPS:               s.PreferHTTPS,
		NoFallback:                s.NoFallback,
		NoFallbackScheme:          s.NoFallbackScheme,
		TechDetect:                s.TechDetect,
		StoreChain:                s.StoreChain,
		OutputExtractRegex:        s.OutputExtractRegex,
		MaxResponseBodySizeToSave: s.MaxResponseBodySizeToSave,
		MaxResponseBodySizeToRead: s.MaxResponseBodySizeToRead,
		HostMaxErrors:             s.HostMaxErrors,
		Favicon:                   s.Favicon,
		LeaveDefaultPorts:         s.LeaveDefaultPorts,
		OutputLinesCount:          s.OutputLinesCount,
		OutputWordsCount:          s.OutputWordsCount,
		Hashes:                    s.Hashes,
	}
}

// Options contains configuration options for httpx.
type Options struct {
	HTMLOutput                bool
	CustomHeaders             customheader.CustomHeaders
	CustomPorts               customport.CustomPorts
	matchStatusCode           []int
	matchContentLength        []int
	filterStatusCode          []int
	filterContentLength       []int
	Output                    string
	StoreResponseDir          string
	HTTPProxy                 string
	SocksProxy                string
	InputFile                 string
	Methods                   string
	RequestURI                string
	RequestURIs               string
	requestURIs               []string
	OutputMatchStatusCode     string
	OutputMatchContentLength  string
	OutputFilterStatusCode    string
	OutputFilterContentLength string
	InputRawRequest           string
	rawRequest                string
	RequestBody               string
	OutputFilterString        string
	OutputMatchString         string
	OutputFilterRegex         string
	OutputMatchRegex          string
	Retries                   int
	Threads                   int
	Timeout                   int
	filterRegex               *regexp.Regexp
	matchRegex                *regexp.Regexp
	VHost                     bool
	VHostInput                bool
	Smuggling                 bool
	ExtractTitle              bool
	StatusCode                bool
	Location                  bool
	ContentLength             bool
	FollowRedirects           bool
	StoreResponse             bool
	JSONOutput                bool
	CSVOutput                 bool
	Silent                    bool
	Version                   bool
	Verbose                   bool
	NoColor                   bool
	OutputServerHeader        bool
	OutputWebSocket           bool
	responseInStdout          bool
	chainInStdout             bool
	FollowHostRedirects       bool
	MaxRedirects              int
	OutputMethod              bool
	TLSProbe                  bool
	CSPProbe                  bool
	OutputContentType         bool
	OutputIP                  bool
	OutputCName               bool
	Unsafe                    bool
	Debug                     bool
	DebugRequests             bool
	DebugResponse             bool
	Pipeline                  bool
	HTTP2Probe                bool
	OutputCDN                 bool
	OutputResponseTime        bool
	NoFallback                bool
	NoFallbackScheme          bool
	TechDetect                bool
	TLSGrab                   bool
	protocol                  string
	ShowStatistics            bool
	StatsInterval             int
	RandomAgent               bool
	StoreChain                bool
	Deny                      customlist.CustomList
	Allow                     customlist.CustomList
	MaxResponseBodySizeToSave int
	MaxResponseBodySizeToRead int
	OutputExtractRegex        string
	RateLimit                 int
	RateLimitMinute           int
	Probe                     bool
	Resume                    bool
	resumeCfg                 *ResumeCfg
	ExcludeCDN                bool
	HostMaxErrors             int
	Stream                    bool
	SkipDedupe                bool
	ProbeAllIPS               bool
	Resolvers                 goflags.NormalizedStringSlice
	Favicon                   bool
	OutputFilterFavicon       goflags.NormalizedStringSlice
	OutputMatchFavicon        goflags.NormalizedStringSlice
	LeaveDefaultPorts         bool
	OutputLinesCount          bool
	OutputMatchLinesCount     string
	matchLinesCount           []int
	OutputFilterLinesCount    string
	filterLinesCount          []int
	OutputWordsCount          bool
	OutputMatchWordsCount     string
	matchWordsCount           []int
	OutputFilterWordsCount    string
	filterWordsCount          []int
	Hashes                    string
	Jarm                      bool
	Asn                       bool
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`httpx是一个快速和多用途的HTTP工具包，允许使用retryablehttp库运行多个探测器.`)

	createGroup(flagSet, "input", "Input",
		flagSet.StringVarP(&options.InputFile, "list", "l", "", "待处理的目标列表文件"),
		flagSet.StringVarP(&options.InputRawRequest, "request", "rr", "", "原始请求文件"),
	)

	createGroup(flagSet, "Probes", "Probes 获取 & 输出",
		flagSet.BoolVarP(&options.StatusCode, "status-code", "sc", false, "响应-状态代码"),
		flagSet.BoolVarP(&options.ContentLength, "content-length", "cl", false, "响应-内容长度"),
		flagSet.BoolVarP(&options.OutputContentType, "content-type", "ct", false, "响应-内容类型"),
		flagSet.BoolVar(&options.Location, "location", false, "响应重定向位置"),
		flagSet.BoolVar(&options.Favicon, "favicon", false, "'/favicon.ico' 文件的mmh3哈希值"),
		flagSet.StringVar(&options.Hashes, "hash", "", "哈希值（支持：MD5,MMH3,SIMHash,SHA1,SHA256,SHA512）。"),
		flagSet.BoolVar(&options.Jarm, "jarm", false, "jarm指纹哈希值"),
		flagSet.BoolVarP(&options.OutputResponseTime, "response-time", "rt", false, "响应时间"),
		flagSet.BoolVarP(&options.OutputLinesCount, "line-count", "lc", false, "响应正文行数"),
		flagSet.BoolVarP(&options.OutputWordsCount, "word-count", "wc", false, "响应body字数"),
		flagSet.BoolVar(&options.ExtractTitle, "title", false, "页面标题"),
		flagSet.BoolVarP(&options.OutputServerHeader, "web-server", "server", false, "display server"),
		flagSet.BoolVarP(&options.TechDetect, "tech-detect", "td", false, "基于Wappalyzer获取指纹"),
		flagSet.BoolVar(&options.OutputMethod, "method", false, "http请求方法"),
		flagSet.BoolVar(&options.OutputWebSocket, "websocket", false, "利用websocket获取服务"),
		flagSet.BoolVar(&options.OutputIP, "ip", false, "display host ip"),
		flagSet.BoolVar(&options.OutputCName, "cname", false, "display host cname"),
		flagSet.BoolVar(&options.Asn, "asn", false, "display host asn information"),
		flagSet.BoolVar(&options.OutputCDN, "cdn", false, "display cdn in use"),
		flagSet.BoolVar(&options.Probe, "probe", false, "显示探头状态"),
	)

	createGroup(flagSet, "matchers", "Matchers & 匹配",
		flagSet.StringVarP(&options.OutputMatchStatusCode, "match-code", "mc", "", "匹配具有指定状态代码的响应 (-mc 200,302)"),
		flagSet.StringVarP(&options.OutputMatchContentLength, "match-length", "ml", "", "匹配指定内容长度的响应 (-ml 100,102)"),
		flagSet.StringVarP(&options.OutputMatchLinesCount, "match-line-count", "mlc", "", "匹配指定行数的响应 (-mlc 423,532)"),
		flagSet.StringVarP(&options.OutputMatchWordsCount, "match-word-count", "mwc", "", "匹配指定字数的响应 (-mwc 43,55)"),
		flagSet.NormalizedStringSliceVarP(&options.OutputMatchFavicon, "match-favicon", "mfc", []string{}, "匹配指定的favicon哈希值响应 (-mfc 1494302000)"),
		flagSet.StringVarP(&options.OutputMatchString, "match-string", "ms", "", "用指定的字符串匹配响应 (-ms admin)"),
		flagSet.StringVarP(&options.OutputMatchRegex, "match-regex", "mr", "", "用正则匹配响应 (-mr admin)"),
	)

	createGroup(flagSet, "extractor", "Extractor & 提取",
		flagSet.StringVarP(&options.OutputExtractRegex, "extract-regex", "er", "", "显示指定的regex的响应内容"),
	)

	createGroup(flagSet, "filters", "Filters & 过滤器",
		flagSet.StringVarP(&options.OutputFilterStatusCode, "filter-code", "fc", "", "过滤指定状态代码的响应 (-fc 403,401)"),
		flagSet.StringVarP(&options.OutputFilterContentLength, "filter-length", "fl", "", "过滤指定内容长度的响应 (-fl 23,33)"),
		flagSet.StringVarP(&options.OutputFilterLinesCount, "filter-line-count", "flc", "", "过滤指定行数的响应 (-flc 423,532)"),
		flagSet.StringVarP(&options.OutputFilterWordsCount, "filter-word-count", "fwc", "", "过滤指定字数的响应 (-fwc 423,532)"),
		flagSet.NormalizedStringSliceVarP(&options.OutputFilterFavicon, "filter-favicon", "ffc", []string{}, "过滤指定的favicon哈希值响应 (-mfc 1494302000)"),
		flagSet.StringVarP(&options.OutputFilterString, "filter-string", "fs", "", "用指定的字符串来过滤响应 (-fs admin)"),
		flagSet.StringVarP(&options.OutputFilterRegex, "filter-regex", "fe", "", "用指定的正则过滤响应 (-fe admin)"),
	)

	createGroup(flagSet, "rate-limit", "Rate-Limit & 速率限制",
		flagSet.IntVarP(&options.Threads, "threads", "t", 50, "线程数"),
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "每秒可发送的最大请求"),
		flagSet.IntVarP(&options.RateLimitMinute, "rate-limit-minute", "rlm", 0, "每分钟发送的最大请求数"),
	)

	createGroup(flagSet, "Misc", "Miscellaneous & 杂项",
		flagSet.BoolVarP(&options.ProbeAllIPS, "probe-all-ips", "pa", false, "探测与同一主机相关的所有ips"),
		flagSet.VarP(&options.CustomPorts, "ports", "p", "探测端口 (nmap syntax: eg 1,2-10,11)"),
		flagSet.StringVar(&options.RequestURIs, "path", "", "探测的路径或路径列表 (comma-separated, file)"),
		flagSet.BoolVar(&options.TLSProbe, "tls-probe", false, "send http probes on the extracted TLS domains (dns_name)"),
		flagSet.BoolVar(&options.CSPProbe, "csp-probe", false, "send http probes on the extracted CSP domains"),
		flagSet.BoolVar(&options.TLSGrab, "tls-grab", false, "perform TLS(SSL) data grabbing"),
		flagSet.BoolVar(&options.Pipeline, "pipeline", false, "探测和显示 server supporting HTTP1.1 pipeline"),
		flagSet.BoolVar(&options.HTTP2Probe, "http2", false, "探测和显示 server supporting HTTP2"),
		flagSet.BoolVar(&options.VHost, "vhost", false, "探测和显示 server supporting VHOST"),
	)

	createGroup(flagSet, "output", "Output & 输出",
		flagSet.StringVarP(&options.Output, "output", "o", "", "输出结果(必要的)"),
		flagSet.BoolVarP(&options.StoreResponse, "store-response", "sr", false, "http响应包到输出目录"),
		flagSet.StringVarP(&options.StoreResponseDir, "store-response-dir", "srd", "", "http响应包到自定义目录"),
		flagSet.BoolVar(&options.HTMLOutput, "html", false, "以html格式输出"),
		flagSet.BoolVar(&options.CSVOutput, "csv", false, "以csv格式输出"),
		flagSet.BoolVar(&options.JSONOutput, "json", false, "以JSONL(ines)格式输出。"),
		flagSet.BoolVarP(&options.responseInStdout, "include-response", "irr", false, "输出http请求/响应的内容到JSON文件 (-json only)"),
		flagSet.BoolVar(&options.chainInStdout, "include-chain", false, "输出请求重定向内容到JSON文件 (-json only)"),
		flagSet.BoolVar(&options.StoreChain, "store-chain", false, "输出请求重定向内容到文件 (-sr only)"),
	)

	createGroup(flagSet, "configs", "Configurations & 配置",
		flagSet.NormalizedStringSliceVarP(&options.Resolvers, "resolvers", "r", []string{}, "自定义解析器列表 (file or comma separated)"),
		flagSet.Var(&options.Allow, "allow", "允许处理的IP/URl的列表 (file or comma separated)"),
		flagSet.Var(&options.Deny, "deny", "禁止处理的IP/URl的列表 (file or comma separated)"),
		flagSet.BoolVar(&options.RandomAgent, "random-agent", true, "启用随机user-agent (默认开启)"),
		flagSet.VarP(&options.CustomHeaders, "header", "H", "自定义请求头 (-H Cookie:k=v)"),
		flagSet.StringVarP(&options.HTTPProxy, "proxy", "http-proxy", "", "http proxy to use (eg http://127.0.0.1:8080)"),
		flagSet.BoolVar(&options.Unsafe, "unsafe", false, "发送原始请求，跳过golang的规范化处理"),
		flagSet.BoolVar(&options.Resume, "resume", false, "使用 resume.cfg 恢复扫描"),
		flagSet.BoolVarP(&options.FollowRedirects, "follow-redirects", "fr", false, "遵循http重定向"),
		flagSet.IntVarP(&options.MaxRedirects, "max-redirects", "maxr", 10, "最大重定向数"),
		flagSet.BoolVarP(&options.FollowHostRedirects, "follow-host-redirects", "fhr", false, "跟随host重定向"),
		flagSet.BoolVar(&options.VHostInput, "vhost-input", false, "get a list of vhosts as input"),
		flagSet.StringVar(&options.Methods, "x", "", "使用所有的HTTP方法探测"),
		flagSet.StringVar(&options.RequestBody, "body", "", "http请求正文"),
		flagSet.BoolVarP(&options.Stream, "stream", "s", false, "顺序探测模式"),
		flagSet.BoolVarP(&options.SkipDedupe, "skip-dedupe", "sd", false, "禁用重复计算的输入项目 (only used with stream mode)"),
		flagSet.BoolVarP(&options.LeaveDefaultPorts, "leave-default-ports", "ldp", false, "header保留默认http/https端口 (eg. http://host:80 - https//host:443"),
	)

	createGroup(flagSet, "debug", "Debug & 调试",
		flagSet.BoolVar(&options.Debug, "debug", false, "在终端中显示请求/响应的内容"),
		flagSet.BoolVar(&options.DebugRequests, "debug-req", false, "在终端中显示请求内容"),
		flagSet.BoolVar(&options.DebugResponse, "debug-resp", false, "在终端中显示响应内容"),
		flagSet.BoolVar(&options.Version, "version", false, "显示 httpx 版本"),
		flagSet.BoolVar(&options.ShowStatistics, "stats", false, "显示扫描统计信息"),
		flagSet.BoolVar(&options.Silent, "silent", false, "静默模式"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "详细模式"),
		flagSet.IntVarP(&options.StatsInterval, "stats-interval", "si", 0, "显示统计资料更新之间的等待秒数 (default: 5)"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "禁用终端输出颜色"),
	)

	createGroup(flagSet, "Optimizations", "Optimizations & 优化",
		flagSet.BoolVarP(&options.NoFallback, "no-fallback", "nf", false, "侦察http/https协议 (HTTPS and HTTP)"),
		flagSet.BoolVarP(&options.NoFallbackScheme, "no-fallback-scheme", "nfs", false, "指定协议方法进行侦察"),
		flagSet.IntVarP(&options.HostMaxErrors, "max-host-error", "maxhr", 30, "在跳过剩余路径之前，每个主机的最大错误数"),
		flagSet.BoolVarP(&options.ExcludeCDN, "exclude-cdn", "ec", false, "跳过CDN端口扫描 (only checks for 80,443)"),
		flagSet.IntVar(&options.Retries, "retries", 0, "重试次数 (-retries 2)"),
		flagSet.IntVar(&options.Timeout, "timeout", 5, "超时, 以秒为单位 (default: 5  -timeout 10)"),
		flagSet.IntVarP(&options.MaxResponseBodySizeToSave, "response-size-to-save", "rsts", math.MaxInt32, "保存的最大响应大小 (字节)"),
		flagSet.IntVarP(&options.MaxResponseBodySizeToRead, "response-size-to-read", "rstr", math.MaxInt32, "读取的最大响应大小 (字节)"),
	)

	_ = flagSet.Parse()

	if options.StatsInterval != 0 {
		options.ShowStatistics = true
	}
	// Read the inputs and configure the logging
	options.configureOutput()

	err := options.configureResume()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	options.validateOptions()

	return options
}

func (options *Options) validateOptions() {
	if options.InputFile != "" && !fileutilz.FileNameIsGlob(options.InputFile) && !fileutil.FileExists(options.InputFile) {
		gologger.Fatal().Msgf("File %s does not exist.\n", options.InputFile)
	}

	if options.InputRawRequest != "" && !fileutil.FileExists(options.InputRawRequest) {
		gologger.Fatal().Msgf("File %s does not exist.\n", options.InputRawRequest)
	}

	multiOutput := options.CSVOutput && options.JSONOutput && options.HTMLOutput
	if multiOutput {
		gologger.Fatal().Msg("Results can only be displayed in one format: 'JSON' or 'CSV' or 'HTML'\n")
	}

	var err error
	if options.matchStatusCode, err = stringz.StringToSliceInt(options.OutputMatchStatusCode); err != nil {
		gologger.Fatal().Msgf("Invalid value for match status code option: %s\n", err)
	}
	if options.matchContentLength, err = stringz.StringToSliceInt(options.OutputMatchContentLength); err != nil {
		gologger.Fatal().Msgf("Invalid value for match content length option: %s\n", err)
	}
	if options.filterStatusCode, err = stringz.StringToSliceInt(options.OutputFilterStatusCode); err != nil {
		gologger.Fatal().Msgf("Invalid value for filter status code option: %s\n", err)
	}
	if options.filterContentLength, err = stringz.StringToSliceInt(options.OutputFilterContentLength); err != nil {
		gologger.Fatal().Msgf("Invalid value for filter content length option: %s\n", err)
	}
	if options.OutputFilterRegex != "" {
		if options.filterRegex, err = regexp.Compile(options.OutputFilterRegex); err != nil {
			gologger.Fatal().Msgf("Invalid value for regex filter option: %s\n", err)
		}
	}
	if options.OutputMatchRegex != "" {
		if options.matchRegex, err = regexp.Compile(options.OutputMatchRegex); err != nil {
			gologger.Fatal().Msgf("Invalid value for match regex option: %s\n", err)
		}
	}
	if options.matchLinesCount, err = stringz.StringToSliceInt(options.OutputMatchLinesCount); err != nil {
		gologger.Fatal().Msgf("Invalid value for match lines count option: %s\n", err)
	}
	if options.matchWordsCount, err = stringz.StringToSliceInt(options.OutputMatchWordsCount); err != nil {
		gologger.Fatal().Msgf("Invalid value for match words count option: %s\n", err)
	}
	if options.filterLinesCount, err = stringz.StringToSliceInt(options.OutputFilterLinesCount); err != nil {
		gologger.Fatal().Msgf("Invalid value for filter lines count option: %s\n", err)
	}
	if options.filterWordsCount, err = stringz.StringToSliceInt(options.OutputFilterWordsCount); err != nil {
		gologger.Fatal().Msgf("Invalid value for filter words count option: %s\n", err)
	}

	var resolvers []string
	for _, resolver := range options.Resolvers {
		if fileutil.FileExists(resolver) {
			chFile, err := fileutil.ReadFile(resolver)
			if err != nil {
				gologger.Fatal().Msgf("Couldn't process resolver file \"%s\": %s\n", resolver, err)
			}
			for line := range chFile {
				resolvers = append(resolvers, line)
			}
		} else {
			resolvers = append(resolvers, resolver)
		}
	}
	options.Resolvers = resolvers
	if len(options.Resolvers) > 0 {
		gologger.Debug().Msgf("Using resolvers: %s\n", strings.Join(options.Resolvers, ","))
	}

	if options.StoreResponse && options.StoreResponseDir == "" {
		gologger.Debug().Msgf("Store response directory not specified, using \"%s\"\n", DefaultOutputDirectory)
		options.StoreResponseDir = DefaultOutputDirectory
	}
	if options.StoreResponseDir != "" && !options.StoreResponse {
		gologger.Debug().Msgf("Store response directory specified, enabling \"sr\" flag automatically\n")
		options.StoreResponse = true
	}

	if options.Favicon {
		gologger.Debug().Msgf("Setting single path to \"favicon.ico\" and ignoring multiple paths settings\n")
		options.RequestURIs = "/favicon.ico"
	}

	if options.Hashes != "" {
		for _, hashType := range strings.Split(options.Hashes, ",") {
			if !slice.StringSliceContains([]string{"md5", "sha1", "sha256", "sha512", "mmh3", "simhash"}, strings.ToLower(hashType)) {
				gologger.Error().Msgf("Unsupported hash type: %s\n", hashType)
			}
		}
	}
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

func (options *Options) configureResume() error {
	options.resumeCfg = &ResumeCfg{}
	if options.Resume && fileutil.FileExists(DefaultResumeFile) {
		return goconfig.Load(&options.resumeCfg, DefaultResumeFile)

	}
	return nil
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume && fileutil.FileExists(DefaultResumeFile)
}

// ShouldSaveResume file
func (options *Options) ShouldSaveResume() bool {
	return true
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}
