// Copyright 2020 Mohammed El Bahja. All rights reserved.
// Use of this source code is governed by a MIT license.

package goph

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"github.com/topxeq/countingwriter"
	"golang.org/x/crypto/ssh"
)

// Client represents Goph client.
type Client struct {
	*ssh.Client
	Config *Config
}

// Config for Client.
type Config struct {
	Auth     Auth
	User     string
	Addr     string
	Port     uint
	Timeout  time.Duration
	Callback ssh.HostKeyCallback
}

// DefaultTimeout is the timeout of ssh client connection.
var DefaultTimeout = 20 * time.Second

// New starts a new ssh connection, the host public key must be in known hosts.
func New(user string, addr string, auth Auth) (c *Client, err error) {

	callback, err := DefaultKnownHosts()

	if err != nil {
		return
	}

	c, err = NewConn(&Config{
		User:     user,
		Addr:     addr,
		Port:     22,
		Auth:     auth,
		Timeout:  DefaultTimeout,
		Callback: callback,
	})
	return
}

// NewUnknown starts a ssh connection get client without cheking knownhosts.
// PLEASE AVOID USING THIS, UNLESS YOU KNOW WHAT ARE YOU DOING!
// if there a "man in the middle proxy", this can harm you!
// You can add the key to know hosts and use New() func instead!
func NewUnknown(user string, addr string, auth Auth) (*Client, error) {
	return NewConn(&Config{
		User:     user,
		Addr:     addr,
		Port:     22,
		Auth:     auth,
		Timeout:  DefaultTimeout,
		Callback: ssh.InsecureIgnoreHostKey(),
	})
}

// NewConn returns new client and error if any.
func NewConn(config *Config) (c *Client, err error) {

	c = &Client{
		Config: config,
	}

	c.Client, err = Dial("tcp", config)
	return
}

// Dial starts a client connection to SSH server based on config.
func Dial(proto string, c *Config) (*ssh.Client, error) {
	return ssh.Dial(proto, net.JoinHostPort(c.Addr, fmt.Sprint(c.Port)), &ssh.ClientConfig{
		User:            c.User,
		Auth:            c.Auth,
		Timeout:         c.Timeout,
		HostKeyCallback: c.Callback,
	})
}

// Run starts a new SSH session and runs the cmd, it returns CombinedOutput and err if any.
func (c Client) Run(cmd string) ([]byte, error) {

	var (
		err  error
		sess *ssh.Session
	)

	if sess, err = c.NewSession(); err != nil {
		return nil, err
	}

	defer sess.Close()

	return sess.CombinedOutput(cmd)
}

// Run starts a new SSH session with context and runs the cmd. It returns CombinedOutput and err if any.
func (c Client) RunContext(ctx context.Context, name string) ([]byte, error) {
	cmd, err := c.CommandContext(ctx, name)
	if err != nil {
		return nil, err
	}

	return cmd.CombinedOutput()
}

// Command returns new Cmd and error if any.
func (c Client) Command(name string, args ...string) (*Cmd, error) {

	var (
		sess *ssh.Session
		err  error
	)

	if sess, err = c.NewSession(); err != nil {
		return nil, err
	}

	return &Cmd{
		Path:    name,
		Args:    args,
		Session: sess,
		Context: context.Background(),
	}, nil
}

// Command returns new Cmd with context and error, if any.
func (c Client) CommandContext(ctx context.Context, name string, args ...string) (*Cmd, error) {
	cmd, err := c.Command(name, args...)
	if err != nil {
		return cmd, err
	}

	cmd.Context = ctx

	return cmd, nil
}

// NewSftp returns new sftp client and error if any.
func (c Client) NewSftp(opts ...sftp.ClientOption) (*sftp.Client, error) {
	return sftp.NewClient(c.Client, opts...)
}

// Close client net connection.
func (c Client) Close() error {
	return c.Client.Close()
}

func GetFilePathSeperator() string {
	osT := runtime.GOOS
	if osT == "windows" {
		return "\\"
	} else {
		return "/"
	}
}

func GetLastComponentOfFilePath(pathA string, sepA ...string) string {
	var sepT string
	if len(sepA) > 0 {
		sepT = sepA[0]
		listT := strings.Split(pathA, sepT)

		return listT[len(listT)-1]
	} else {
		sepT = GetFilePathSeperator()
	}

	if strings.HasSuffix(pathA, sepT) {
		return ""
	} else {
		return filepath.Base(pathA)
	}
}

func GetSwitch(argsA []string, switchStrA string, defaultA ...string) string {

	ifDefaultT := true
	var defaultT string

	if defaultA == nil || len(defaultA) < 1 {
		ifDefaultT = false
	}

	if ifDefaultT {
		defaultT = defaultA[0]
	}

	if argsA == nil {
		if ifDefaultT {
			return defaultT
		}
		return ""
	}

	if len(argsA) < 1 {
		if ifDefaultT {
			return defaultT
		}
		return ""
	}

	tmpStrT := ""
	for _, argT := range argsA {
		if strings.HasPrefix(argT, switchStrA) {
			tmpStrT = argT[len(switchStrA):]
			if strings.HasPrefix(tmpStrT, "\"") && strings.HasSuffix(tmpStrT, "\"") {
				return tmpStrT[1 : len(tmpStrT)-1]
			}

			return tmpStrT
		}

	}

	if ifDefaultT {
		return defaultT
	}
	return ""
}

func IfSwitchExists(argsA []string, switchStrA string) bool {
	if argsA == nil {
		return false
	}

	if len(argsA) < 1 {
		return false
	}

	for _, argT := range argsA {
		if argT == switchStrA {
			return true
		}

	}

	return false
}

// Upload a local file to remote server!
func (c Client) Upload(localPath string, remotePath string, optsA ...string) (err error) {

	local, err := os.Open(localPath)
	if err != nil {
		return
	}
	defer local.Close()

	ftp, err := c.NewSftp()
	if err != nil {
		return
	}
	defer ftp.Close()

	ifResumeT := IfSwitchExists(optsA, "-resume")

	if ifResumeT {
		b1, errT := c.IfFileExists(remotePath)
		if errT != nil {
			err = errT
			return
		}

		var remote *sftp.File

		var oldLenT int64 = 0

		if b1 {
			var fi fs.FileInfo
			fi, err = ftp.Stat(remotePath)

			if err != nil && !os.IsExist(err) {
				return
			}

			if fi.IsDir() {
				err = fmt.Errorf("is dir")
				return
			}

			oldLenT = fi.Size()

			remote, err = ftp.OpenFile(remotePath, os.O_RDWR|os.O_CREATE|os.O_APPEND)
			if err != nil {
				return
			}
			defer remote.Close()

			var offsetT int64
			offsetT, err = local.Seek(oldLenT, 0)
			if err != nil {
				return
			}

			if offsetT != oldLenT {
				err = fmt.Errorf("seek offset failed: %v", offsetT)
				return
			}

			// fmt.Printf("resume from offset %v\n", offsetT)

		} else {
			remote, err = ftp.Create(remotePath)
			if err != nil {
				return
			}
			defer remote.Close()

		}

		_, err = io.Copy(remote, local)
		return

	}

	ifForceT := IfSwitchExists(optsA, "-force")

	if !ifForceT {
		b1, errT := c.IfFileExists(remotePath)
		if errT != nil {
			err = errT
			return
		}

		if b1 {
			err = fmt.Errorf("file already exists")
			return
		}
	}

	var remote *sftp.File

	remote, err = ftp.Create(remotePath)
	if err != nil {
		return
	}
	defer remote.Close()

	_, err = io.Copy(remote, local)
	return
}

func (c Client) UploadWithProgressFunc(localPath string, remotePath string, funcA func(interface{}) interface{}, optsA ...string) (err error) {
	defer func() {
		r := recover()

		if r != nil {
			err = fmt.Errorf("failed to upload: %v", r)
			return
		}

		// if funcA != nil {
		// 	funcA("-1|failed to upload: exception")
		// }
	}()

	local, err := os.Open(localPath)
	if err != nil {
		return
	}
	defer local.Close()

	ftp, err := c.NewSftp()
	if err != nil {
		return
	}
	defer ftp.Close()

	var multiWriterT io.Writer

	ifResumeT := IfSwitchExists(optsA, "-resume")

	if ifResumeT {
		b1, errT := c.IfFileExists(remotePath)
		if errT != nil {
			err = errT
			return
		}

		var remote *sftp.File

		var oldLenT int64 = 0

		if b1 {
			var fi fs.FileInfo
			fi, err = ftp.Stat(remotePath)

			if err != nil && !os.IsExist(err) {
				return
			}

			if fi.IsDir() {
				err = fmt.Errorf("is dir")
				return
			}

			oldLenT = fi.Size()

			remote, err = ftp.OpenFile(remotePath, os.O_RDWR|os.O_CREATE|os.O_APPEND)
			if err != nil {
				return
			}
			defer remote.Close()

			var offsetT int64
			offsetT, err = local.Seek(oldLenT, 0)
			if err != nil {
				return
			}

			if offsetT != oldLenT {
				err = fmt.Errorf("seek offset failed: %v", offsetT)
				return
			}

			// fmt.Printf("resume from offset %v\n", offsetT)

		} else {
			remote, err = ftp.Create(remotePath)
			if err != nil {
				return
			}
			defer remote.Close()

		}

		if funcA != nil {
			multiWriterT = io.MultiWriter(remote, countingwriter.NewCountingWriter(nil, funcA))
		} else {
			multiWriterT = remote
		}

		_, err = io.Copy(multiWriterT, local)
		return

	}

	ifForceT := IfSwitchExists(optsA, "-force")

	if !ifForceT {
		b1, errT := c.IfFileExists(remotePath)
		if errT != nil {
			err = errT
			return
		}

		if b1 {
			err = fmt.Errorf("file already exists")
			return
		}
	}

	var remote *sftp.File

	remote, err = ftp.Create(remotePath)
	if err != nil {
		return
	}
	defer remote.Close()

	if funcA != nil {
		multiWriterT = io.MultiWriter(remote, countingwriter.NewCountingWriter(nil, funcA))
	} else {
		multiWriterT = remote
	}

	_, err = io.Copy(multiWriterT, local)
	return
}

func (c Client) UploadFileContent(contentA []byte, remotePath string, optsA ...string) (err error) {

	ftp, err := c.NewSftp()
	if err != nil {
		return
	}
	defer ftp.Close()

	ifForceT := IfSwitchExists(optsA, "-force")

	ifAppendT := IfSwitchExists(optsA, "-append")

	if !ifForceT && !ifAppendT {
		b1, errT := c.IfFileExists(remotePath)
		if errT != nil {
			err = errT
			return
		}

		if b1 {
			err = fmt.Errorf("file already exists")
			return
		}
	}

	var remote *sftp.File

	if ifAppendT {
		remote, err = ftp.OpenFile(remotePath, os.O_RDWR|os.O_CREATE|os.O_APPEND)
		if err != nil {
			return
		}
		defer remote.Close()
	} else {
		remote, err = ftp.Create(remotePath)
		if err != nil {
			return
		}
		defer remote.Close()
	}

	bytesT := bytes.NewBuffer(contentA)

	_, err = io.Copy(remote, bytesT)

	return
}

func IsDirectory(dirNameA string) bool {
	f, err := os.Open(dirNameA)
	if err != nil {
		return false
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return false
	}

	if mode := fi.Mode(); mode.IsDir() {
		return true
	}

	return false
}

func IfFileExists(fileNameA string) bool {
	_, err := os.Stat(fileNameA)
	return err == nil || os.IsExist(err)
}

// Download file from remote server!
func (c Client) Download(remotePath string, localPath string, optsA ...string) (err error) {
	if IsDirectory(localPath) {
		err = fmt.Errorf("target is a directory")
		return
	}

	ifForceT := IfSwitchExists(optsA, "-force")

	if IfFileExists(localPath) {
		if !ifForceT {
			err = fmt.Errorf("file already exists")
			return
		}
	}

	local, err := os.Create(localPath)
	if err != nil {
		return
	}
	defer local.Close()

	ftp, err := c.NewSftp()
	if err != nil {
		return
	}
	defer ftp.Close()

	remote, err := ftp.Open(remotePath)
	if err != nil {
		return
	}
	defer remote.Close()

	if _, err = io.Copy(local, remote); err != nil {
		return
	}

	return local.Sync()
}

func (c Client) GetFileContent(remotePath string, optsA ...string) ([]byte, error) {

	var local bytes.Buffer

	ftp, err := c.NewSftp()
	if err != nil {
		return nil, err
	}
	defer ftp.Close()

	remote, err := ftp.Open(remotePath)
	if err != nil {
		return nil, err
	}
	defer remote.Close()

	if _, err = io.Copy(&local, remote); err != nil {
		return nil, err
	}

	return local.Bytes(), nil
}

func (c Client) GetFileInfo(remotePath string) (map[string]string, error) {

	ftp, err := c.NewSftp()
	if err != nil {
		return nil, err
	}
	defer ftp.Close()

	fi, err := ftp.Stat(remotePath)

	if err != nil && !os.IsExist(err) {
		return nil, err
	}

	mapT := map[string]string{"Path": remotePath, "Abs": remotePath, "Name": filepath.Base(remotePath), "Ext": filepath.Ext(remotePath), "Size": fmt.Sprintf("%v", fi.Size()), "IsDir": fmt.Sprintf("%v", fi.IsDir()), "Time": fi.ModTime().Format("20060102150405"), "Mode": fmt.Sprintf("%v", fi.Mode())}

	return mapT, nil
}

func (c Client) IfFileExists(remotePath string) (bool, error) {

	ftp, err := c.NewSftp()
	if err != nil {
		return false, err
	}
	defer ftp.Close()

	_, err = ftp.Stat(remotePath)

	if err != nil {
		if os.IsExist(err) {
			return true, nil
		} else {
			return false, nil
		}
	}

	return true, nil
}

func (c Client) MakeDir(remotePath string) error {

	ftp, err := c.NewSftp()
	if err != nil {
		return err
	}
	defer ftp.Close()

	err = ftp.Mkdir(remotePath)

	if err != nil {
		return err
	}

	return nil
}

func (c Client) EnsureMakeDirs(remotePath string) error {

	ftp, err := c.NewSftp()
	if err != nil {
		return err
	}
	defer ftp.Close()

	err = ftp.MkdirAll(remotePath)

	if err != nil {
		return err
	}

	return nil
}

func (c Client) RemoveDir(remotePath string) error {

	ftp, err := c.NewSftp()
	if err != nil {
		return err
	}
	defer ftp.Close()

	err = ftp.RemoveDirectory(remotePath)

	if err != nil {
		return err
	}

	return nil
}

func (c Client) RemoveFile(remotePath string) error {

	ftp, err := c.NewSftp()
	if err != nil {
		return err
	}
	defer ftp.Close()

	err = ftp.Remove(remotePath)

	if err != nil {
		return err
	}

	return nil
}

func (c Client) JoinPath(elem ...string) string {

	ftp, err := c.NewSftp()
	if err != nil {
		return "TXERROR:failed to create sftp object"
	}
	defer ftp.Close()

	return ftp.Join(elem...)

}

func (c Client) Rename(oldname, newname string) error {

	ftp, err := c.NewSftp()
	if err != nil {
		return err
	}
	defer ftp.Close()

	err = ftp.Rename(oldname, newname)

	if err != nil {
		return err
	}

	return nil
}

func (c Client) RealPath(path string) (string, error) {

	ftp, err := c.NewSftp()
	if err != nil {
		return path, err
	}
	defer ftp.Close()

	return ftp.RealPath(path)

}

func (c Client) SimpleWalk(pathA string, patternA string) ([]string, error) {

	if patternA == "" {
		patternA = "*"
	}

	ftp, err := c.NewSftp()
	if err != nil {
		return nil, err
	}
	defer ftp.Close()

	itemsT := make([]string, 0)

	walker := ftp.Walk(pathA)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			return nil, err
		}

		tmpPathT := walker.Path()

		b1, errT := filepath.Match(patternA, tmpPathT)

		if errT != nil {
			return nil, errT
		}

		if b1 {
			itemsT = append(itemsT, tmpPathT)
		}
	}

	return itemsT, nil
}

func (c Client) Walk(pathA string, argsA ...string) ([]string, error) {

	sepT := GetSwitch(argsA, "-sep=", "/")
	patternT := GetSwitch(argsA, "-pattern=", "*")
	if patternT == "" {
		patternT = "*"
	}

	withDirT := IfSwitchExists(argsA, "-withDir")
	dirOnlyT := IfSwitchExists(argsA, "-dirOnly")

	ifRecursiveT := IfSwitchExists(argsA, "-recursive")

	ftp, err := c.NewSftp()
	if err != nil {
		return nil, err
	}
	defer ftp.Close()

	itemsT := make([]string, 0)

	walker := ftp.Walk(pathA)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			return nil, err
		}

		fiT := walker.Stat()

		if fiT == nil {
			continue
		}

		tmpPathT := walker.Path()

		// fmt.Printf("fi: %#v, %v\n", fiT, tmpPathT)

		isDirT := fiT.IsDir()

		if isDirT && tmpPathT == pathA {
			continue
		}

		// if isDirT && (!ifRecursiveT) {
		// 	if withDirT || dirOnlyT {
		// 		itemsT = append(itemsT, tmpPathT)
		// 	}

		// 	walker.SkipDir()
		// 	continue
		// }

		// fmt.Printf("GetLastComponentOfFilePath: %#v\n", GetLastComponentOfFilePath(tmpPathT, sepT))

		b1, errT := filepath.Match(patternT, GetLastComponentOfFilePath(tmpPathT, sepT))

		// fmt.Printf("patternT: %#v, fnT: %v, bool: %v\n", patternT, GetLastComponentOfFilePath(tmpPathT, sepT), b1)

		if errT != nil {
			return nil, errT
		}

		if b1 {
			if isDirT {
				if !ifRecursiveT {
					if withDirT || dirOnlyT {
						itemsT = append(itemsT, tmpPathT)
					}

					walker.SkipDir()
					continue
				}

				if withDirT || dirOnlyT {
					itemsT = append(itemsT, tmpPathT)
				}
			} else {
				if !dirOnlyT {
					itemsT = append(itemsT, tmpPathT)
				}
			}
		}
	}

	return itemsT, nil
}
