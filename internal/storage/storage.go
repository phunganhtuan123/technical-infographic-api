// Package storage keeps uploaded files out of the database.
//
// Only a local-disk implementation ships today. That is a deliberate stopping
// point rather than an oversight: it works on one machine and for self-hosting
// without pulling in a cloud SDK, and the interface is the seam where an S3 or
// R2 adapter goes when there is more than one machine. Nothing above this
// package knows where bytes live.
package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Storage interface {
	Put(ctx context.Context, key string, reader io.Reader) (int64, error)
	Open(ctx context.Context, key string) (io.ReadSeekCloser, error)
	Delete(ctx context.Context, key string) error
}

type LocalDisk struct {
	root string
}

func NewLocalDisk(root string) (*LocalDisk, error) {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("create asset directory: %w", err)
	}
	return &LocalDisk{root: root}, nil
}

// path shards on the first two characters of the key so one directory does not
// end up holding a hundred thousand files.
func (l *LocalDisk) path(key string) (string, error) {
	// Keys are generated here, never taken from a request, but check anyway:
	// a key that escaped the root would be a file-write primitive.
	if key == "" || strings.Contains(key, "..") || strings.ContainsAny(key, `/\`) {
		return "", fmt.Errorf("unsafe storage key %q", key)
	}
	if len(key) < 2 {
		return "", fmt.Errorf("storage key too short")
	}
	return filepath.Join(l.root, key[:2], key), nil
}

func (l *LocalDisk) Put(_ context.Context, key string, reader io.Reader) (int64, error) {
	target, err := l.path(key)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return 0, err
	}

	// Write beside the target and rename, so a failed upload never leaves a
	// half-written file that later reads as a corrupt image.
	temporary, err := os.CreateTemp(filepath.Dir(target), ".upload-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(temporary.Name())

	written, err := io.Copy(temporary, reader)
	if err != nil {
		temporary.Close()
		return 0, err
	}
	if err := temporary.Close(); err != nil {
		return 0, err
	}
	if err := os.Chmod(temporary.Name(), 0o640); err != nil {
		return 0, err
	}
	if err := os.Rename(temporary.Name(), target); err != nil {
		return 0, err
	}
	return written, nil
}

func (l *LocalDisk) Open(_ context.Context, key string) (io.ReadSeekCloser, error) {
	target, err := l.path(key)
	if err != nil {
		return nil, err
	}
	return os.Open(target)
}

func (l *LocalDisk) Delete(_ context.Context, key string) error {
	target, err := l.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
