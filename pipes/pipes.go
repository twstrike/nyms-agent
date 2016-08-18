package pipes

import "io"

type pipePair struct {
	input  io.ReadCloser
	output io.WriteCloser
}

func (pp pipePair) Read(p []byte) (int, error) {
	return pp.input.Read(p)
}

func (pp pipePair) Write(p []byte) (int, error) {
	return pp.output.Write(p)
}

func (pp pipePair) Close() (e error) {
	if err := pp.input.Close(); err != nil {
		e = err
	}

	if err := pp.output.Close(); err != nil && e == nil {
		e = err
	}

	return e
}

func CreatePipePair(r io.ReadCloser, w io.WriteCloser) io.ReadWriteCloser {
	return &pipePair{r, w}
}
