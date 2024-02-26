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
	"unsafe"
	//"runtime/pprof"
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
	fmt.Println("Worker Start ",id)
	ioctlBuffer := make([]int,512)
	for {
		index := rand.Intn(len(Targets))
		readCount := rand.Intn(len(Buffer))
		writeCount := rand.Intn(len(Buffer))
		target := Targets[index]
		fmt.Printf("[%d] FUZZING %s\n",id,target.Name)
		fptr, err := os.OpenFile(target.Name, os.O_RDONLY | os.O_WRONLY, 0)
		if err == nil {
			r, _ := fptr.Read(Buffer[0:readCount])
			w, _ := fptr.Write(Buffer[0:writeCount])
			if r > 0 || w > 0 {
				fmt.Printf("READ %d WROTE %d\n",r,w)
			}
			for i := 0x0; i < 0xFFFF; i++ {
				_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fptr.Fd()), uintptr(i), uintptr(unsafe.Pointer(&ioctlBuffer[0])))
				if errno == 0 {}
			}
		}
		fptr.Close()
	}
	fmt.Println("Worker End ",id)
	wg.Done()
}

func test(){
	someBuffer := make([]int,512)
	id := 0
	fmt.Printf("[%d] FUZZING %s\n",id,"/dev/null")
	fptr, err := os.OpenFile("/dev/null", os.O_WRONLY,0)
	if err != nil {
		panic("Failed to open /dev/null")
	}
	for i := 0; i < 0xFFFFFFF; i++ {
		_, _, errno := syscall.RawSyscall6(syscall.SYS_IOCTL, uintptr(fptr.Fd()), uintptr(i), uintptr(unsafe.Pointer(&someBuffer[0])),uintptr(0),uintptr(0),uintptr(0))
		if errno == 0 {
			// extract first 8 bits for command
			// extract second 8 bits for command
			command := int8(i)
			sequence := i & (((1 << 8) - 1) << 8) // start at bit 8 and get the next 8
			direction := i & (((1 << 2) - 1) << 16) // start at bit 16 and get the next 2
			size := i & (((1 << 14) - 1) << 18) // start at bit 18 and get the next 14
			fmt.Printf("0x%X ::: 0x%X ::: 0x%X ::: 0x%X ::: 0x%X \n",i,command,sequence,direction,size)
		}
	}
	fptr.Close()
	fmt.Printf("[%d] FUZZING %s COMPLETE \n",id,"/dev/null")
}

func main(){
	//https://www.goodwith.tech/blog/go-pprof
	/*f, err := os.Create("cpu.pprof")
	if err != nil {
		panic(err)
	}*/
	var wg sync.WaitGroup
	rand.Seed(0x41)
	filepath.WalkDir("/dev",visitCallback)
	filepath.WalkDir("/sys",visitCallback)
	fmt.Println("[+] Done Gathering Targets ")
	//pprof.StartCPUProfile(f)
	//defer pprof.StopCPUProfile()
	//test()
	for id := 1; id < 2; id++ {
		wg.Add(1)
		go loop(id, &wg)
	}
	wg.Wait()
	fmt.Println("Done")
}
