package phaul

import (
	"fmt"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/checkpoint-restore/criu/lib/go/src/criu"
	"github.com/checkpoint-restore/criu/lib/go/src/rpc"
)

type PhaulServer struct {
	cfg     PhaulConfig
	imgs    *images
	cr      *criu.Criu
	process *os.Process
}

/*
 * Main entry point. Make the server with comm and call PhaulRemote
 * methods on it upon client requests.
 */
func MakePhaulServer(c PhaulConfig) (*PhaulServer, error) {
	img, err := preparePhaulImages(c.Wdir)
	if err != nil {
		return nil, err
	}

	cr := criu.MakeCriu()

	return &PhaulServer{imgs: img, cfg: c, cr: cr}, nil
}

/*
 * PhaulRemote methods
 */
func (s *PhaulServer) StartIter() error {
	fmt.Printf("S: start iter\n")
	psi := rpc.CriuPageServerInfo{
		Fd: proto.Int32(int32(s.cfg.Memfd)),
	}
	opts := rpc.CriuOpts{
		LogLevel: proto.Int32(4),
		LogFile:  proto.String("ps.log"),
		Ps:       &psi,
	}

	prev_p := s.imgs.lastImagesDir()
	img_dir, err := s.imgs.openNextDir()
	if err != nil {
		return err
	}
	defer img_dir.Close()

	opts.ImagesDirFd = proto.Int32(int32(img_dir.Fd()))
	if prev_p != "" {
		opts.ParentImg = proto.String(prev_p)
	}

	pid, _, err := s.cr.StartPageServerChld(opts)
	if err != nil {
		return err
	}

	s.process, err = os.FindProcess(pid)
	if err != nil {
		return err
	}

	return nil
}

func (s *PhaulServer) StopIter() error {
	state, err := s.process.Wait()
	if err != nil {
		return nil
	}

	if !state.Success() {
		return fmt.Errorf("page-server failed: %s", s)
	}
	return nil
}

/*
 * Server-local methods
 */
func (s *PhaulServer) LastImagesDir() string {
	return s.imgs.lastImagesDir()
}

func (s *PhaulServer) GetCriu() *criu.Criu {
	return s.cr
}
