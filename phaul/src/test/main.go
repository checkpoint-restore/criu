package main

import (
	"criu"
	"fmt"
	"github.com/golang/protobuf/proto"
	"os"
	"phaul"
	"rpc"
	"strconv"
	"strings"
	"syscall"
)

type testLocal struct {
	criu.CriuNoNotify
	r *testRemote
}

type testRemote struct {
	srv *phaul.PhaulServer
}

/* Dir where test will put dump images */
const images_dir = "test_images"

func prepareImages() error {
	err := os.Mkdir(images_dir, 0700)
	if err != nil {
		return err
	}

	/* Work dir for PhaulClient */
	err = os.Mkdir(images_dir+"/local", 0700)
	if err != nil {
		return err
	}

	/* Work dir for PhaulServer */
	err = os.Mkdir(images_dir+"/remote", 0700)
	if err != nil {
		return err
	}

	/* Work dir for DumpCopyRestore */
	err = os.Mkdir(images_dir+"/test", 0700)
	if err != nil {
		return err
	}

	return nil
}

func mergeImages(dump_dir, last_pre_dump_dir string) error {
	idir, err := os.Open(dump_dir)
	if err != nil {
		return err
	}

	defer idir.Close()

	imgs, err := idir.Readdirnames(0)
	if err != nil {
		return err
	}

	for _, fname := range imgs {
		if !strings.HasSuffix(fname, ".img") {
			continue
		}

		fmt.Printf("\t%s -> %s/\n", fname, last_pre_dump_dir)
		err = syscall.Link(dump_dir+"/"+fname, last_pre_dump_dir+"/"+fname)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *testRemote) doRestore() error {
	last_srv_images_dir := r.srv.LastImagesDir()
	/*
	 * In images_dir we have images from dump, in the
	 * last_srv_images_dir -- where server-side images
	 * (from page server, with pages and pagemaps) are.
	 * Need to put former into latter and restore from
	 * them.
	 */
	err := mergeImages(images_dir+"/test", last_srv_images_dir)
	if err != nil {
		return err
	}

	img_dir, err := os.Open(last_srv_images_dir)
	if err != nil {
		return err
	}
	defer img_dir.Close()

	opts := rpc.CriuOpts{
		LogLevel:    proto.Int32(4),
		LogFile:     proto.String("restore.log"),
		ImagesDirFd: proto.Int32(int32(img_dir.Fd())),
	}

	cr := r.srv.GetCriu()
	fmt.Printf("Do restore\n")
	return cr.Restore(opts, nil)
}

func (l *testLocal) PostDump() error {
	return l.r.doRestore()
}

func (l *testLocal) DumpCopyRestore(cr *criu.Criu, cfg phaul.PhaulConfig, last_cln_images_dir string) error {
	fmt.Printf("Final stage\n")

	img_dir, err := os.Open(images_dir + "/test")
	if err != nil {
		return err
	}
	defer img_dir.Close()

	psi := rpc.CriuPageServerInfo{
		Fd: proto.Int32(int32(cfg.Memfd)),
	}

	opts := rpc.CriuOpts{
		Pid:         proto.Int32(int32(cfg.Pid)),
		LogLevel:    proto.Int32(4),
		LogFile:     proto.String("dump.log"),
		ImagesDirFd: proto.Int32(int32(img_dir.Fd())),
		TrackMem:    proto.Bool(true),
		ParentImg:   proto.String(last_cln_images_dir),
		Ps:          &psi,
	}

	fmt.Printf("Do dump\n")
	return cr.Dump(opts, l)
}

func main() {
	pid, _ := strconv.Atoi(os.Args[1])
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Printf("Can't make socketpair\n")
		return
	}

	err = prepareImages()
	if err != nil {
		fmt.Printf("Can't prepare dirs for images\n")
		return
	}

	fmt.Printf("Make server part (socket %d)\n", fds[1])
	srv, err := phaul.MakePhaulServer(phaul.PhaulConfig{
		Pid:   pid,
		Memfd: fds[1],
		Wdir:  images_dir + "/remote"})
	if err != nil {
		return
	}

	r := &testRemote{srv}

	fmt.Printf("Make client part (socket %d)\n", fds[0])
	cln, err := phaul.MakePhaulClient(&testLocal{r: r}, srv,
		phaul.PhaulConfig{
			Pid:   pid,
			Memfd: fds[0],
			Wdir:  images_dir + "/local"})
	if err != nil {
		return
	}

	fmt.Printf("Migrate\n")
	err = cln.Migrate()
	if err != nil {
		fmt.Printf("Failed: ")
		fmt.Print(err)
		return
	}

	fmt.Printf("SUCCESS!\n")
}
