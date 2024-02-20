package main

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"os"
	"math/rand"
	"bytes"
	"sync"
	"syscall"
	"strings"
)

var Targets = make([]FileEntry,0)
var Buffer = bytes.Repeat([]byte{0x1F},0x1024)

// track?
type Fuzzer struct {
	Cases float64
	CasesPerSecond float64
}

type FileEntry struct {
	Name string
	ValidIoctl []int
}

func visitCallback(path string, d fs.DirEntry, err error) error {
	if err != nil {
		return fs.SkipDir
	}
	if strings.HasPrefix(path,"/dev/tty"){
		return fs.SkipDir
	}
	if !d.IsDir() {
		entry := FileEntry{Name:path}
		Targets = append(Targets,entry)
	}
	return nil
}

func loop(id int, wg *sync.WaitGroup){
	//fmt.Println("Worker Start ",id)
	for x := 0; x < len(Targets); x++ {
		index := x
		readCount := rand.Intn(len(Buffer))
		writeCount := rand.Intn(len(Buffer))
		target := Targets[index]
		fmt.Printf("[+] FUZZING %s\n",target.Name)
		rptr, err := os.OpenFile(target.Name, os.O_RDONLY,0)
		if err == nil {
			rptr.Read(Buffer[0:readCount])
			for i := 0x0; i < 0xffff; i++ {
				_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(rptr.Fd()), uintptr(i), uintptr(0))
				if errno == 0 {
					fmt.Printf("IOCTL WORKED %x\n",i)
				}
			}
			rptr.Close()
		}
		wptr, err := os.OpenFile(target.Name, os.O_WRONLY,0)
		if err == nil {
			wptr.Write(Buffer[0:writeCount])
			for i := 0x0; i < 0xffff; i++ {
				_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(wptr.Fd()), uintptr(i), uintptr(0))
				if errno == 0 {
					fmt.Printf("IOCTL WORKED %x\n",i)
				}
			}
			wptr.Close()
		}
	}
	//time.Sleep(10 * time.Second)
	//fmt.Println("Worker End ",id)
	wg.Done()
}


func main(){
	var wg sync.WaitGroup
	rand.Seed(0x41)
	filepath.WalkDir("/dev",visitCallback)
	filepath.WalkDir("/sys",visitCallback)
	fmt.Println("[+] Done Gathering Targets ")
	for id := 1; id < 2; id++ {
		wg.Add(1)
		go loop(id, &wg)
	}
	wg.Wait()
	fmt.Println("Done")
}
