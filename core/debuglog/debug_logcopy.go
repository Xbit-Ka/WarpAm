/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 110, debug feature: a copy of the ordinary log.
 *
 * Every line that goes into log.bin goes into the debug file as well, so
 * nothing is lost when the ring wraps after 2048 lines. That includes the
 * lines of Wintun itself: wintun.dll writes through the same log.
 */

package debuglog

import (
	"io"
	"log"
	"time"
)

func init() {
	Register("log copy", true, func() {
		log.SetOutput(&tee{inner: log.Writer()})
	})
}

// timestampedWriter is what the ring log offers and what Wintun looks for
// in the writer of the log, so the copy has to offer it too.
type timestampedWriter interface {
	WriteWithTimestamp(p []byte, ts int64) (n int, err error)
}

type tee struct {
	inner io.Writer
}

func (t *tee) Write(p []byte) (int, error) {
	n, err := t.inner.Write(p)
	writeLine(time.Now(), string(p))
	return n, err
}

func (t *tee) WriteWithTimestamp(p []byte, ts int64) (int, error) {
	var n int
	var err error
	if tw, ok := t.inner.(timestampedWriter); ok {
		n, err = tw.WriteWithTimestamp(p, ts)
	} else {
		n, err = t.inner.Write(p)
	}
	writeLine(time.Unix(0, ts), string(p))
	return n, err
}
