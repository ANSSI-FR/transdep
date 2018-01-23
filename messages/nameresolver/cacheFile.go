package nameresolver

import (
	"bufio"
	"bytes"
	"encoding/json"
	"github.com/miekg/dns"
	"io"
	"os"
	"strings"
	"github.com/ANSSI-FR/transdep/errors"
)

// CACHE_DIRNAME is the name of the directory under the cache root directory for storage of name resolution cache files
const CACHE_DIRNAME = "nameresolver"

// CreateCacheDir creates the cache dir for storage of name resolution cache files.
// It may return an error if the directory cannot be created. If the directory already exists, this function does
// nothing.
func CreateCacheDir(cacheRootDir string) error {
	if err := os.MkdirAll(cacheRootDir+string(os.PathSeparator)+CACHE_DIRNAME, 0700); !os.IsExist(err) {
		return err
	}
	return nil
}

// CacheFile represents just that.
type CacheFile struct {
	fileName string
}

// NewCacheFile initializes a new CacheFile struct, based on the cache root dir, and the name of the domain that is the
// subject of this cache file.
func NewCacheFile(cacheRootDir string, topic RequestTopic) *CacheFile {
	buf := new(bytes.Buffer)
	buf.WriteString(cacheRootDir)
	buf.WriteRune(os.PathSeparator)
	buf.WriteString(CACHE_DIRNAME)
	buf.WriteRune(os.PathSeparator)
	buf.WriteString("nr-")
	buf.WriteString(strings.ToLower(dns.Fqdn(topic.Name)))
	buf.WriteString("-")

	if topic.Exceptions.RFC8020 {
		buf.WriteString("1")
	} else {
		buf.WriteString("0")
	}

	if topic.Exceptions.AcceptServFailAsNoData {
		buf.WriteString("1")
	} else {
		buf.WriteString("0")
	}

	fileName := buf.String()

	cf := &CacheFile{fileName}
	return cf
}

// NewCacheFile initializes a new CacheFile struct and ensures that this file exists or else returns an error.
func NewExistingCacheFile(cacheRootDir string, topic RequestTopic) (*CacheFile, error) {
	cf := NewCacheFile(cacheRootDir, topic)
	fd, err := os.Open(cf.fileName)
	defer fd.Close()
	return cf, err
}

/* Result returns the entry or the error that were stored in the cache file. An error may also be returned, if an
incident happens during retrieval/interpretation of the cache file.

entry is the entry that was stored in the cache file.

resultError is the resolution error that was stored in the cache file.

err is the error that may happen during retrieval of the value in the cache file.
*/
func (cf *CacheFile) Result() (entry *Entry, resultError *errors.ErrorStack, err error) {
	fd, err := os.Open(cf.fileName)
	if err != nil {
		return nil, nil, err
	}
	defer fd.Close()

	buffedFd := bufio.NewReader(fd)
	// For some reason, a null byte is appended at the end of the file. Not sure why, but let's use it :)
	jsonbstr, err := buffedFd.ReadBytes('\x00')
	if err != nil && err != io.EOF {
		return nil, nil, err
	}

	res := new(result)
	err = json.Unmarshal(jsonbstr, res)
	if err != nil {
		return nil, nil, err
	}
	return res.Result, res.Err, nil
}

// SetResult writes in the cache file the provided entry or error. An error is returned if an incident happens or else
// nil is returned.
func (cf *CacheFile) SetResult(entry *Entry, resultErr *errors.ErrorStack) error {
	var jsonRepr []byte
	var err error
	var fd *os.File

	if jsonRepr, err = json.Marshal(&result{entry, resultErr}); err != nil {
		return err
	}

	if fd, err = os.OpenFile(cf.fileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600); err != nil {
		return err
	}
	fd.WriteString(string(jsonRepr))
	fd.Close()
	return nil
}
