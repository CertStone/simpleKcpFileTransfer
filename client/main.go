package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"certstone.cc/simpleKcpFileTransfer/common"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// 全局 Session 管理 (保持不变)
var globalSession *smux.Session
var sessionMutex sync.Mutex

// 全局密钥
var globalKey string
var keyMutex sync.RWMutex

const (
	defaultWorkers    = 8
	defaultChunkSize  = 4 * 1024 * 1024 // 4 MiB per range request
	maxParallelTasks  = 3               // queue cap for simultaneous downloads
	connectionTimeout = 3 * time.Second // 连接超时时间
)

var taskSemaphore = make(chan struct{}, maxParallelTasks)

// 获取当前密钥
func getCurrentKey() string {
	keyMutex.RLock()
	defer keyMutex.RUnlock()
	return globalKey
}

// 设置密钥并重置会话
func setKey(key string) {
	keyMutex.Lock()
	defer keyMutex.Unlock()
	globalKey = key
	// 关闭旧会话，强制重新连接
	sessionMutex.Lock()
	if globalSession != nil && !globalSession.IsClosed() {
		globalSession.Close()
	}
	globalSession = nil
	sessionMutex.Unlock()
}

func runOnUI(f func()) {
	fyne.Do(f)
}

func getSession(address string) (*smux.Session, error) {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	if globalSession != nil && !globalSession.IsClosed() {
		return globalSession, nil
	}

	type connResult struct {
		session *smux.Session
		err     error
	}
	resultCh := make(chan connResult, 1)

	// 使用 context 控制超时，确保超时时能清理资源
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel() // 确保 context 总是被取消

	go func() {
		crypt, _ := common.GetBlockCrypt(getCurrentKey())
		kcpConn, err := kcp.DialWithOptions(address, crypt, 10, 3)
		if err != nil {
			resultCh <- connResult{err: err}
			return
		}
		common.ConfigKCP(kcpConn)

		session, err := smux.Client(kcpConn, common.SmuxConfig())
		if err != nil {
			kcpConn.Close()
			resultCh <- connResult{err: err}
			return
		}

		// 打开一个测试流
		testStream, err := session.OpenStream()
		if err != nil {
			session.Close()
			resultCh <- connResult{err: fmt.Errorf("open stream failed: %w", err)}
			return
		}

		// 关键：设置流的超时，并进行实际的网络通信来验证连接
		testStream.SetDeadline(time.Now().Add(connectionTimeout))

		// 发送一个简单的 HTTP HEAD 请求
		_, err = testStream.Write([]byte("HEAD / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"))
		if err != nil {
			testStream.Close()
			session.Close()
			resultCh <- connResult{err: fmt.Errorf("connection failed: %w", err)}
			return
		}

		// 读取响应 - 这是真正验证连接的地方
		// 如果密钥错误，服务端无法解密数据，不会响应，Read 会超时
		buf := make([]byte, 1)
		_, err = testStream.Read(buf)
		testStream.Close()
		if err != nil {
			session.Close()
			resultCh <- connResult{err: fmt.Errorf("connection failed (possibly wrong key): %w", err)}
			return
		}

		// 检查是否已超时取消
		select {
		case <-ctx.Done():
			// 已超时，清理资源
			session.Close()
			return
		case resultCh <- connResult{session: session}:
			// 成功发送结果
		}
	}()

	// 等待连接结果或超时
	select {
	case result := <-resultCh:
		if result.err != nil {
			return nil, result.err
		}
		globalSession = result.session
		return result.session, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("connection timeout (server unreachable or wrong key)")
	}
}

func newKCPHTTPClient(serverAddr string) *http.Client {
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		sess, err := getSession(serverAddr)
		if err != nil {
			return nil, err
		}
		return sess.OpenStream()
	}
	return &http.Client{Transport: &http.Transport{DialContext: dialer}}
}

func fetchRemoteFiles(serverAddr, relPath string, recursive bool) ([]RemoteFile, error) {
	client := newKCPHTTPClient(serverAddr)
	q := "?action=list"
	if relPath != "" {
		q += "&path=" + url.QueryEscape(relPath)
	}
	if recursive {
		q += "&recursive=1"
	}
	resp, err := client.Get(fmt.Sprintf("http://%s/%s", serverAddr, q))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var files []RemoteFile
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, err
	}
	return files, nil
}

type DownloadOptions struct {
	ServerAddr string
	FileURL    string
	SaveDir    string
	Workers    int
	ChunkSize  int64
	Ctx        context.Context
	OnProgress func(percent float64, speedMBps float64)
	OnStatus   func(msg string)
}

type RemoteFile struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"modTime"`
	IsDir   bool   `json:"isDir"`
}

type checksumMismatchError struct {
	Remote string
	Local  string
}

func (c checksumMismatchError) Error() string {
	return "checksum mismatch"
}

// ensureLeadingSlash guarantees the URL path has a leading slash
func ensureLeadingSlash(path string) string {
	if path == "" {
		return "/"
	}
	if path[0] != '/' {
		return "/" + path
	}
	return path
}

// 计算本地文件 SHA256
func calcLocalChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// progressWriter wraps an io.Writer and reports progress in real-time
type progressWriter struct {
	writer     io.WriterAt
	offset     int64
	downloaded *atomic.Int64
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.writer.WriteAt(p, pw.offset)
	pw.offset += int64(n)
	pw.downloaded.Add(int64(n))
	return n, err
}

// performDownload handles range-based multi-threaded download with resume and checksum verification.
func performDownload(opts DownloadOptions) error {
	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Workers <= 0 {
		opts.Workers = defaultWorkers
	}
	if opts.ChunkSize <= 0 {
		opts.ChunkSize = defaultChunkSize
	}
	fileURL := ensureLeadingSlash(opts.FileURL)
	fullURL := fmt.Sprintf("http://%s%s", opts.ServerAddr, fileURL)
	client := newKCPHTTPClient(opts.ServerAddr)

	if opts.OnStatus != nil {
		opts.OnStatus("Connecting...")
	}
	headReq, _ := http.NewRequestWithContext(ctx, "HEAD", fullURL, nil)
	headResp, err := client.Do(headReq)
	if err != nil {
		return fmt.Errorf("head request failed: %w", err)
	}
	defer headResp.Body.Close()
	fileSize := headResp.ContentLength
	if fileSize <= 0 {
		return fmt.Errorf("unknown remote file size")
	}

	fileName := filepath.Base(fileURL)
	destPath := filepath.Join(opts.SaveDir, fileName)
	os.MkdirAll(opts.SaveDir, 0755)

	var startByte int64
	if info, err := os.Stat(destPath); err == nil {
		startByte = info.Size()
	}
	if startByte > fileSize {
		os.Remove(destPath)
		startByte = 0
	}

	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open dest file: %w", err)
	}
	defer f.Close()
	if err := f.Truncate(fileSize); err != nil {
		return fmt.Errorf("preallocate file: %w", err)
	}

	// Build chunk list
	type chunk struct{ start, end int64 }
	var chunks []chunk
	for offset := startByte; offset < fileSize; offset += opts.ChunkSize {
		end := offset + opts.ChunkSize - 1
		if end >= fileSize {
			end = fileSize - 1
		}
		chunks = append(chunks, chunk{start: offset, end: end})
	}

	downloaded := atomic.Int64{}
	downloaded.Store(startByte)
	var progressMu sync.Mutex
	lastBytes := startByte
	var lastTick time.Time
	var lastSpeed float64 // 保存上次计算的速度，避免显示跳动
	downloadStarted := false

	// updateProgress calculates and reports progress/speed
	updateProgress := func() {
		if opts.OnProgress == nil {
			return
		}
		progressMu.Lock()
		defer progressMu.Unlock()

		cur := downloaded.Load()
		percent := float64(cur) / float64(fileSize)

		if downloadStarted {
			now := time.Now()
			elapsed := now.Sub(lastTick)
			deltaBytes := cur - lastBytes

			// 每次都计算速度（只要有时间流逝）
			if elapsed > 0 {
				// 计算这段时间内的速度
				currentSpeed := float64(deltaBytes) / elapsed.Seconds() / 1024.0 / 1024.0
				if currentSpeed < 0 {
					currentSpeed = 0
				}

				// 使用平滑算法：新速度 = 0.3*旧速度 + 0.7*当前速度
				// 这样可以避免速度跳动太厉害
				if lastSpeed > 0 && currentSpeed > 0 {
					lastSpeed = 0.3*lastSpeed + 0.7*currentSpeed
				} else {
					lastSpeed = currentSpeed
				}

				// 更新基准点
				lastBytes = cur
				lastTick = now
			}
		}

		opts.OnProgress(percent, lastSpeed)
	}

	// 标记下载开始，初始化计时
	startTiming := func() {
		progressMu.Lock()
		defer progressMu.Unlock()
		if !downloadStarted {
			downloadStarted = true
			lastTick = time.Now()
			lastBytes = downloaded.Load()
			lastSpeed = 0
		}
	}

	// Early exit if already complete
	if len(chunks) == 0 {
		if opts.OnProgress != nil {
			opts.OnProgress(1, 0)
		}
		return verifyChecksum(client, fullURL, destPath)
	}

	stopTicker := make(chan struct{})
	defer close(stopTicker)

	// Send initial progress immediately
	if opts.OnProgress != nil {
		opts.OnProgress(float64(startByte)/float64(fileSize), 0)
	}

	// background ticker - updates progress every second
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				updateProgress()
			case <-stopTicker:
				return
			}
		}
	}()

	if opts.OnStatus != nil {
		opts.OnStatus("Downloading...")
	}

	// 标记下载真正开始
	startTiming()

	chunkCh := make(chan chunk, len(chunks))
	errCh := make(chan error, opts.Workers)
	var wg sync.WaitGroup

	for _, c := range chunks {
		chunkCh <- c
	}
	close(chunkCh)

	workerCount := opts.Workers
	if workerCount > len(chunks) {
		workerCount = len(chunks)
	}
	if workerCount == 0 {
		workerCount = 1
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range chunkCh {
				if ctx.Err() != nil {
					return
				}
				req, _ := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
				req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", c.start, c.end))
				resp, err := client.Do(req)
				if err != nil {
					errCh <- fmt.Errorf("range %d-%d: %w", c.start, c.end, err)
					return
				}
				if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
					resp.Body.Close()
					errCh <- fmt.Errorf("range %d-%d: unexpected status %s", c.start, c.end, resp.Status)
					return
				}
				writer := &progressWriter{
					writer:     f,
					offset:     c.start,
					downloaded: &downloaded,
				}
				remaining := c.end - c.start + 1
				written, err := io.CopyN(writer, resp.Body, remaining)
				if err != nil && !errors.Is(err, io.EOF) {
					resp.Body.Close()
					errCh <- fmt.Errorf("range %d-%d copy: %w", c.start, c.end, err)
					return
				}
				if written != remaining {
					resp.Body.Close()
					errCh <- fmt.Errorf("range %d-%d short read: %d/%d", c.start, c.end, written, remaining)
					return
				}
				resp.Body.Close()
				// downloaded 已经在 progressWriter.Write 中实时更新，无需再 Add
			}
		}()
	}

	wg.Wait()
	close(errCh)
	if len(errCh) > 0 {
		return <-errCh
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	updateProgress()

	if opts.OnStatus != nil {
		opts.OnStatus("Verifying Checksum...")
	}
	if err := verifyChecksumWithContext(ctx, client, fullURL, destPath); err != nil {
		return err
	}
	if opts.OnProgress != nil {
		opts.OnProgress(1, 0)
	}
	return nil
}

func verifyChecksum(client *http.Client, fullURL, destPath string) error {
	return verifyChecksumWithContext(context.Background(), client, fullURL, destPath)
}

func verifyChecksumWithContext(ctx context.Context, client *http.Client, fullURL, destPath string) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", fullURL+"?action=checksum", nil)
	respSum, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch remote checksum: %w", err)
	}
	defer respSum.Body.Close()
	remoteHashBytes, err := io.ReadAll(respSum.Body)
	if err != nil {
		return fmt.Errorf("read remote checksum: %w", err)
	}
	remoteHash := string(remoteHashBytes)

	localHash, err := calcLocalChecksum(destPath)
	if err != nil {
		return fmt.Errorf("calculate local checksum: %w", err)
	}

	if remoteHash != localHash {
		return checksumMismatchError{Remote: remoteHash, Local: localHash}
	}
	return nil
}

func runCLIMode(addr, fileURL, saveDir string, workers int) error {
	opts := DownloadOptions{
		ServerAddr: addr,
		FileURL:    fileURL,
		SaveDir:    saveDir,
		Workers:    workers,
		ChunkSize:  defaultChunkSize,
		OnStatus: func(msg string) {
			fmt.Println(msg)
		},
		OnProgress: func(percent float64, speedMBps float64) {
			fmt.Printf("\rProgress: %.1f%% (%.2f MB/s)", percent*100, speedMBps)
		},
	}
	if err := performDownload(opts); err != nil {
		fmt.Println()
		return err
	}
	fmt.Println("\nCompleted & Verified ✔")
	fmt.Print("\007")
	return nil
}

// showKeyInputDialog 显示密钥输入对话框
func showKeyInputDialog(window fyne.Window, onConfirm func(key string)) {
	keyEntry := widget.NewPasswordEntry()
	keyEntry.SetPlaceHolder("Enter encryption key")

	content := container.NewVBox(
		widget.NewLabel("Connection failed. The server may be using a custom encryption key."),
		widget.NewLabel("Please enter the server's encryption key:"),
		keyEntry,
	)

	dialog.ShowCustomConfirm("Encryption Key Required", "Connect", "Cancel", content, func(confirm bool) {
		if confirm {
			onConfirm(keyEntry.Text)
		}
	}, window)
}

func main() {
	addrFlag := flag.String("addr", "127.0.0.1:8080", "KCP server address")
	urlFlag := flag.String("url", "", "Remote file path, e.g. /video.mp4 (CLI mode)")
	outDirFlag := flag.String("out", "./download", "Directory to save downloaded files (CLI mode)")
	workersFlag := flag.Int("workers", defaultWorkers, "Parallel workers per download (CLI mode)")
	cliFlag := flag.Bool("cli", false, "Run without GUI and download via CLI")
	keyFlag := flag.String("key", "", "Encryption key (default: built-in key)")
	flag.Parse()

	// 初始化全局密钥
	globalKey = *keyFlag

	if *cliFlag {
		if *urlFlag == "" {
			log.Fatal("-url is required in CLI mode")
		}
		if err := runCLIMode(*addrFlag, *urlFlag, *outDirFlag, *workersFlag); err != nil {
			log.Fatal(err)
		}
		return
	}

	myApp := app.New()
	myWindow := myApp.NewWindow("KCP High-Speed Downloader")
	myWindow.Resize(fyne.NewSize(950, 600))

	addrEntry := widget.NewEntry()
	addrEntry.SetText(*addrFlag)
	saveDir := *outDirFlag
	os.MkdirAll(saveDir, 0755)

	saveDirLabel := widget.NewLabel("Save to: " + saveDir)
	tasksContainer := container.NewVBox()
	listStatus := widget.NewLabel("Press Connect to browse")

	var serverFiles []RemoteFile
	var loadList func(relPath string)
	currentPath := ""
	selectedFile := (*RemoteFile)(nil)
	var downloadFolderBtn *widget.Button
	infoLabel := widget.NewLabel("Select a file or folder")
	pathLabel := widget.NewLabel("/")

	formatSize := func(sz int64) string {
		if sz < 1024 {
			return fmt.Sprintf("%d B", sz)
		}
		mb := float64(sz) / 1024.0 / 1024.0
		return fmt.Sprintf("%.2f MB", mb)
	}

	updateInfo := func(f *RemoteFile) {
		if f == nil {
			infoLabel.SetText("Select a file or folder")
			if downloadFolderBtn != nil {
				downloadFolderBtn.Disable()
			}
			return
		}
		mt := time.Unix(f.ModTime, 0).Format("2006-01-02 15:04:05")
		kind := "File"
		if f.IsDir {
			kind = "Folder"
		}
		infoLabel.SetText(fmt.Sprintf("%s | %s | %s", kind, formatSize(f.Size), mt))
		if downloadFolderBtn != nil {
			if f.IsDir {
				downloadFolderBtn.Enable()
			} else {
				downloadFolderBtn.Disable()
			}
		}
	}

	fileList := widget.NewList(
		func() int { return len(serverFiles) },
		func() fyne.CanvasObject {
			icon := widget.NewIcon(nil)
			nameBtn := widget.NewButton("", nil)
			nameBtn.Importance = widget.HighImportance
			openBtn := widget.NewButton("Open", nil)
			openBtn.Importance = widget.LowImportance
			row := container.NewHBox(icon, nameBtn, openBtn)
			return row
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			row := o.(*fyne.Container)
			icon := row.Objects[0].(*widget.Icon)
			nameBtn := row.Objects[1].(*widget.Button)
			openBtn := row.Objects[2].(*widget.Button)
			if i >= len(serverFiles) {
				nameBtn.SetText("")
				nameBtn.OnTapped = nil
				openBtn.Hide()
				openBtn.OnTapped = nil
				return
			}
			f := serverFiles[i]
			if f.IsDir {
				icon.SetResource(theme.FolderIcon())
				openBtn.Show()
			} else {
				icon.SetResource(theme.FileIcon())
				openBtn.Hide()
			}
			nameBtn.SetText(fmt.Sprintf("%s (%s)", f.Name, formatSize(f.Size)))
			nameBtn.OnTapped = func() {
				selectedFile = &f
				updateInfo(selectedFile)
			}
			openBtn.OnTapped = func() {
				selectedFile = &f
				updateInfo(selectedFile)
				currentPath = path.Join(currentPath, f.Name)
				pathLabel.SetText("/" + currentPath)
				loadList(currentPath)
			}
		},
	)

	// 核心下载逻辑（并行分块 + 校验 + 可暂停）
	var startDownload func(serverAddr, fileUrl string, bar *widget.ProgressBar, status *widget.Label, retryBtn, pauseBtn, resumeBtn, cancelBtn *widget.Button, isCanceled func() bool, setCancel func(context.CancelFunc))

	startDownload = func(serverAddr, fileUrl string, bar *widget.ProgressBar, status *widget.Label, retryBtn, pauseBtn, resumeBtn, cancelBtn *widget.Button, isCanceled func() bool, setCancel func(context.CancelFunc)) {
		retryBtn.Hide()
		resumeBtn.Hide()
		pauseBtn.Show()
		if cancelBtn != nil {
			cancelBtn.Enable()
		}
		fileUrl = ensureLeadingSlash(fileUrl)
		fileName := filepath.Base(fileUrl)
		destPath := filepath.Join(saveDir, fileName)

		ctx, cancel := context.WithCancel(context.Background())
		setCancel(cancel)

		taskSemaphore <- struct{}{}
		go func() {
			defer func() { <-taskSemaphore }()
			opts := DownloadOptions{
				ServerAddr: serverAddr,
				FileURL:    fileUrl,
				SaveDir:    saveDir,
				Workers:    defaultWorkers,
				ChunkSize:  defaultChunkSize,
				Ctx:        ctx,
				OnStatus: func(msg string) {
					runOnUI(func() { status.SetText(msg) })
				},
				OnProgress: func(percent float64, speedMBps float64) {
					runOnUI(func() {
						bar.SetValue(percent)
						if speedMBps > 0 {
							status.SetText(fmt.Sprintf("Downloading: %.2f MB/s", speedMBps))
						}
					})
				},
			}

			if err := performDownload(opts); err != nil {
				if errors.Is(err, context.Canceled) {
					runOnUI(func() {
						if isCanceled != nil && isCanceled() {
							status.SetText("Canceled")
							bar.SetValue(0)
							retryBtn.Hide()
							pauseBtn.Hide()
							resumeBtn.Hide()
							if cancelBtn != nil {
								cancelBtn.Disable()
							}
						} else {
							status.SetText("Paused")
							retryBtn.Hide()
							pauseBtn.Hide()
							resumeBtn.Show()
						}
					})
					if isCanceled != nil && isCanceled() {
						_ = os.Remove(destPath)
					}
					return
				}

				runOnUI(func() {
					status.SetText("Error")
					bar.SetValue(0)
					retryBtn.Show()
					pauseBtn.Hide()
					resumeBtn.Show()
				})

				if cm, ok := err.(checksumMismatchError); ok {
					runOnUI(func() {
						content := container.NewVBox(
							widget.NewLabel("Checksum mismatch"),
							widget.NewLabel(fmt.Sprintf("Remote: %s...", cm.Remote[:8])),
							widget.NewLabel(fmt.Sprintf("Local: %s...", cm.Local[:8])),
						)
						dialog.ShowCustom("Integrity Check Failed", "Close", content, myWindow)
					})
				} else {
					runOnUI(func() {
						dialog.ShowError(err, myWindow)
					})
				}
				return
			}

			runOnUI(func() {
				status.SetText("Completed & Verified ✔")
				bar.SetValue(1.0)
				pauseBtn.Hide()
				retryBtn.Hide()
				resumeBtn.Hide()
				if cancelBtn != nil {
					cancelBtn.Disable()
				}
			})
			fmt.Print("\007")
			runOnUI(func() { dialog.ShowInformation("Success", fileName+" download completed!", myWindow) })
		}()
	}

	// 添加任务到界面
	addTask := func(serverAddr, fileUrl string) {
		if serverAddr == "" || fileUrl == "" {
			return
		}
		serverAddr = strings.TrimSpace(serverAddr)
		if serverAddr == "" {
			return
		}

		fileName := filepath.Base(fileUrl)

		statusLabel := widget.NewLabel("Pending: " + fileName)
		progressBar := widget.NewProgressBar()

		retryBtn := widget.NewButtonWithIcon("Retry", theme.ViewRefreshIcon(), nil)
		retryBtn.Hide()
		pauseBtn := widget.NewButton("Pause", nil)
		resumeBtn := widget.NewButton("Resume", nil)
		resumeBtn.Hide()
		cancelBtn := widget.NewButtonWithIcon("Cancel", theme.CancelIcon(), nil)

		destPath := filepath.Join(saveDir, fileName)

		var cancelFn context.CancelFunc
		manualCancel := atomic.Bool{}
		paused := atomic.Bool{}
		_ = paused.Load // suppress unused warning if needed

		// 重试逻辑：删除文件，重新开始
		retryBtn.OnTapped = func() {
			// 使用闭包捕获的 destPath，而不是重新计算
			for i := 0; i < 5; i++ {
				if err := os.Remove(destPath); err == nil || os.IsNotExist(err) {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			progressBar.SetValue(0)
			manualCancel.Store(false)
			paused.Store(false)
			startDownload(serverAddr, fileUrl, progressBar, statusLabel, retryBtn, pauseBtn, resumeBtn, cancelBtn, manualCancel.Load, func(c context.CancelFunc) { cancelFn = c })
		}

		pauseBtn.OnTapped = func() {
			paused.Store(true)
			if cancelFn != nil {
				cancelFn()
			}
		}

		resumeBtn.OnTapped = func() {
			retryBtn.Hide()
			progressBar.SetValue(progressBar.Value)
			manualCancel.Store(false)
			paused.Store(false)
			startDownload(serverAddr, fileUrl, progressBar, statusLabel, retryBtn, pauseBtn, resumeBtn, cancelBtn, manualCancel.Load, func(c context.CancelFunc) { cancelFn = c })
		}

		cancelBtn.OnTapped = func() {
			manualCancel.Store(true)
			wasPaused := paused.Load()
			if cancelFn != nil {
				cancelFn()
			}
			statusLabel.SetText("Canceled")
			progressBar.SetValue(0)
			cancelBtn.Disable()
			retryBtn.Hide()
			pauseBtn.Hide()
			resumeBtn.Hide()
			// 如果已暂停，协程已退出，需要主动删除文件
			// 如果未暂停，协程会处理删除，但我们也尝试删除以确保
			go func() {
				// 等待协程退出和文件句柄释放
				if wasPaused {
					time.Sleep(100 * time.Millisecond)
				} else {
					time.Sleep(500 * time.Millisecond)
				}
				// 多次尝试删除
				for i := 0; i < 10; i++ {
					if err := os.Remove(destPath); err == nil || os.IsNotExist(err) {
						return
					}
					time.Sleep(200 * time.Millisecond)
				}
			}()
		}

		buttonBar := container.NewHBox(pauseBtn, resumeBtn, retryBtn, cancelBtn)

		// 任务行布局
		taskRow := container.NewVBox(
			container.NewBorder(nil, nil, widget.NewLabel(fileName), buttonBar, statusLabel),
			progressBar,
			widget.NewSeparator(),
		)

		tasksContainer.Add(taskRow)

		// 立即开始
		manualCancel.Store(false)
		startDownload(serverAddr, fileUrl, progressBar, statusLabel, retryBtn, pauseBtn, resumeBtn, cancelBtn, manualCancel.Load, func(c context.CancelFunc) { cancelFn = c })
	}

	btnSetDir := widget.NewButton("Set Dir", func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if uri != nil {
				saveDir = uri.Path()
				saveDirLabel.SetText("Save to: " + saveDir)
			}
		}, myWindow)
	})

	upBtn := widget.NewButton("Up", func() {
		if currentPath == "" {
			return
		}
		currentPath = path.Dir(currentPath)
		if currentPath == "." {
			currentPath = ""
		}
		pathLabel.SetText("/" + currentPath)
		loadList(currentPath)
	})

	var loadListBtn *widget.Button
	var connectBtn *widget.Button
	var listLoading atomic.Bool

	loadList = func(relPath string) {
		if listLoading.Load() {
			return
		}
		serverAddr := strings.TrimSpace(addrEntry.Text)
		if serverAddr == "" {
			return
		}
		if relPath == "." {
			relPath = ""
		}
		runOnUI(func() {
			addrEntry.SetText(serverAddr)
			pathLabel.SetText("/" + relPath)
			listStatus.SetText("Loading...")
			if loadListBtn != nil {
				loadListBtn.Disable()
			}
			if connectBtn != nil {
				connectBtn.Disable()
			}
		})
		listLoading.Store(true)
		go func() {
			files, err := fetchRemoteFiles(serverAddr, relPath, false)
			if err != nil {
				runOnUI(func() {
					listStatus.SetText("Load failed: " + err.Error())
					// 连接失败时，弹出密钥输入对话框
					showKeyInputDialog(myWindow, func(newKey string) {
						setKey(newKey)
						// 重新尝试连接
						listLoading.Store(false)
						loadList(relPath)
					})
				})
			} else {
				runOnUI(func() {
					serverFiles = files
					selectedFile = nil
					updateInfo(nil)
					listStatus.SetText(fmt.Sprintf("%d items", len(files)))
					fileList.Refresh()
				})
			}
			listLoading.Store(false)
			runOnUI(func() {
				if loadListBtn != nil {
					loadListBtn.Enable()
				}
				if connectBtn != nil {
					connectBtn.Enable()
				}
			})
		}()
	}

	loadListBtn = widget.NewButton("Refresh", func() {
		loadList(currentPath)
	})

	queueFolderDownload := func() {
		if selectedFile == nil || !selectedFile.IsDir {
			return
		}
		serverAddr := strings.TrimSpace(addrEntry.Text)
		if serverAddr == "" {
			return
		}
		runOnUI(func() { listStatus.SetText("Preparing folder download...") })
		folderPath := selectedFile.Path
		go func() {
			files, err := fetchRemoteFiles(serverAddr, folderPath, true)
			if err != nil {
				runOnUI(func() { listStatus.SetText("Load failed: " + err.Error()) })
				return
			}
			for _, f := range files {
				if f.IsDir {
					continue
				}
				ff := f
				runOnUI(func() { addTask(serverAddr, ff.Path) })
			}
			runOnUI(func() { listStatus.SetText("Folder queued") })
		}()
	}

	downloadFileBtn := widget.NewButtonWithIcon("Download File", theme.DownloadIcon(), func() {
		if selectedFile == nil || selectedFile.IsDir {
			return
		}
		addTask(strings.TrimSpace(addrEntry.Text), selectedFile.Path)
	})
	downloadFolderBtn = widget.NewButtonWithIcon("Download Folder", theme.DownloadIcon(), func() {
		if selectedFile == nil || !selectedFile.IsDir {
			return
		}
		queueFolderDownload()
	})
	downloadFolderBtn.Disable()

	listControls := container.NewBorder(nil, nil, pathLabel, nil, container.NewHBox(loadListBtn, upBtn))
	listFooter := container.NewVBox(infoLabel, container.NewHBox(downloadFileBtn, downloadFolderBtn), listStatus)
	fileListScroll := container.NewVScroll(fileList)
	fileListScroll.SetMinSize(fyne.NewSize(0, 360))
	listCard := widget.NewCard("Remote Files", "Browse and select items", container.NewBorder(listControls, listFooter, nil, nil, fileListScroll))

	header := widget.NewLabelWithStyle("KCP Downloader", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	subHeader := widget.NewLabel("Browse, select, and download files or folders over KCP")
	connectBtn = widget.NewButton("Connect", func() {
		currentPath = ""
		loadList("")
	})
	serverCard := widget.NewCard("Server", "Address and save location", container.NewVBox(
		container.NewBorder(nil, nil, nil, connectBtn, addrEntry),
		container.NewHBox(saveDirLabel, btnSetDir),
	))

	tasksScroll := container.NewVScroll(tasksContainer)
	tasksScroll.SetMinSize(fyne.NewSize(0, 220))
	tasksCard := widget.NewCard("Tasks", "Active & completed downloads", tasksScroll)

	leftPane := container.NewVBox(
		header,
		subHeader,
		serverCard,
		tasksCard,
	)

	mainSplit := container.NewHSplit(leftPane, listCard)
	mainSplit.SetOffset(0.42)

	myWindow.SetContent(mainSplit)

	myWindow.ShowAndRun()
}
