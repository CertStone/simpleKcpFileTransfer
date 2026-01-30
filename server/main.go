package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"certstone.cc/simpleKcpFileTransfer/common"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// 用于缓存文件 Hash，避免重复计算
var hashCache sync.Map

// 计算文件 SHA256
func getFileChecksum(path string) (string, error) {
	// 1. 查缓存
	if val, ok := hashCache.Load(path); ok {
		return val.(string), nil
	}

	// 2. 计算
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	sum := hex.EncodeToString(h.Sum(nil))

	// 3. 存缓存 (实际生产中应该监听文件变化清除缓存)
	hashCache.Store(path, sum)
	return sum, nil
}

type listItem struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"modTime"`
	IsDir   bool   `json:"isDir"`
}

func cleanRelPath(rel string) string {
	if rel == "" {
		return ""
	}
	clean := path.Clean("/" + rel)
	clean = strings.TrimPrefix(clean, "/")
	// 防止目录穿越
	if strings.HasPrefix(clean, "..") || strings.Contains(clean, "/../") {
		return ""
	}
	return clean
}

// isPathSafe 检查路径是否安全（防止目录穿越）
func isPathSafe(root, requestPath string) (string, bool) {
	// 清理路径
	cleanPath := path.Clean("/" + requestPath)
	// 构建完整路径
	fullPath := filepath.Join(root, filepath.FromSlash(cleanPath))
	// 获取绝对路径
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", false
	}
	// 确保路径在 root 目录下
	if !strings.HasPrefix(absPath, absRoot+string(filepath.Separator)) && absPath != absRoot {
		return "", false
	}
	return fullPath, true
}

func listFiles(root, rel string, recursive bool) ([]listItem, error) {
	rel = cleanRelPath(rel)
	target, safe := isPathSafe(root, rel)
	if !safe {
		return nil, os.ErrPermission
	}
	if recursive {
		var items []listItem
		err := filepath.WalkDir(target, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == target {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			relPath, _ := filepath.Rel(root, p)
			items = append(items, listItem{
				Name:    d.Name(),
				Path:    "/" + filepath.ToSlash(relPath),
				Size:    info.Size(),
				ModTime: info.ModTime().Unix(),
				IsDir:   info.IsDir(),
			})
			return nil
		})
		return items, err
	}

	entries, err := os.ReadDir(target)
	if err != nil {
		return nil, err
	}
	var items []listItem
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, listItem{
			Name:    e.Name(),
			Path:    "/" + path.Join(rel, e.Name()),
			Size:    info.Size(),
			ModTime: info.ModTime().Unix(),
			IsDir:   info.IsDir(),
		})
	}
	return items, nil
}

// 包装 FileServer，增加 checksum 和列表功能
func checksumHandler(root string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s from %s", r.Method, r.URL.String(), r.RemoteAddr)
		// 如果 URL 带了 ?action=checksum 参数，则返回 Hash
		switch r.URL.Query().Get("action") {
		case "checksum":
			filePath, safe := isPathSafe(root, r.URL.Path)
			if !safe {
				http.Error(w, "Invalid path", http.StatusBadRequest)
				return
			}
			sum, err := getFileChecksum(filePath)
			if err != nil {
				http.Error(w, "File not found or unreadable", http.StatusNotFound)
				return
			}
			w.Write([]byte(sum))
			return
		case "list":
			rel := r.URL.Query().Get("path")
			recursive := r.URL.Query().Get("recursive") == "1"
			files, err := listFiles(root, rel, recursive)
			if err != nil {
				http.Error(w, "Cannot list files", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(files)
			return
		}
		// 否则正常下载文件
		h.ServeHTTP(w, r)
	})
}

func main() {
	port := flag.String("p", "8080", "Port to listen")
	dir := flag.String("d", ".", "Directory to serve")
	key := flag.String("key", "", "Encryption key (default: built-in key)")
	flag.Parse()

	// 检查是否使用默认密钥
	if common.IsDefaultKey(*key) {
		log.Println("\033[33m[WARNING] Using default encryption key. For production use, please specify a custom key with -key parameter!\033[0m")
	}

	// KCP 监听
	crypt, _ := common.GetBlockCrypt(*key)
	listener, err := kcp.ListenWithOptions(":"+*port, crypt, 10, 3)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("KCP File Server serving %s on :%s", *dir, *port)

	for {
		conn, err := listener.AcceptKCP()
		if err != nil {
			continue
		}
		common.ConfigKCP(conn)

		go func(c *kcp.UDPSession) {
			mux, err := smux.Server(c, common.SmuxConfig())
			if err != nil {
				c.Close()
				return
			}
			defer mux.Close()

			smuxLis := &common.SmuxListener{Session: mux}

			// 使用带 Hash 功能的 Handler
			fileHandler := http.FileServer(http.Dir(*dir))
			wrappedHandler := checksumHandler(*dir, fileHandler)

			// 服务端为每个连接启动一个 HTTP Server 实例
			http.Serve(smuxLis, wrappedHandler)
		}(conn)
	}
}
