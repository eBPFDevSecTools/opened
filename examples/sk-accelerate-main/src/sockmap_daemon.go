package main

import (
    "fmt"
    "os"
    "os/exec"
    "os/signal"
    "syscall"
    "io"
    "time"
    "log"
    "github.com/moby/sys/mountinfo"
)

func cleanup() {

    mount, err := cgroup2Mount()
    if (err == nil) {
        fmt.Printf("Cgroup2 mount point: %s\n", mount)
    } else {
        log.Fatal(err)
    }

    // Unload and detach ebpf program in the reverse order
    fmt.Print("Detaching sockmap program...")
    cmd := exec.Command("/opt/sockmap/bpftool", "prog", "detach", "pinned", "/sys/fs/bpf/bpf_redir", "msg_verdict", "pinned", "/sys/fs/bpf/sock_ops_map")
    err = cmd.Run()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Done")

    fmt.Print("Deleting sockmap program...")
    cmd = exec.Command("/bin/rm", "-f", "/sys/fs/bpf/bpf_redir")
    err = cmd.Run()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Done")

    fmt.Print("Detaching sockops program...")
    cmd = exec.Command("/opt/sockmap/bpftool", "cgroup", "detach", mount, "sock_ops", "pinned", "/sys/fs/bpf/sockop")
    err = cmd.Run()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Done")

    fmt.Print("Deleting sockops program...")
    cmd = exec.Command("/bin/rm", "-f", "/sys/fs/bpf/sockop")
    err = cmd.Run()
    if err != nil {
        log.Fatal(err)
    }
    cmd = exec.Command("/bin/rm", "-f", "/sys/fs/bpf/sock_ops_map")
    err = cmd.Run()
    if err != nil {
        log.Fatal(err)
    }
    cmd = exec.Command("/bin/rm", "-f", "/sys/fs/bpf/endpoints_to_service_map")
    err = cmd.Run()
    if err != nil {
        log.Fatal(err)
    }
    cmd = exec.Command("/bin/rm", "-f", "/sys/fs/bpf/sock_ops_aux_map")
    err = cmd.Run()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Done")

}

func fileCopy(src, dst string) error {
    srcFileStat, err := os.Stat(src)
    if err != nil {
        return err
    }

    if !srcFileStat.Mode().IsRegular() {
        return fmt.Errorf("%s is not a regular file", src)
    }

    source, err := os.Open(src)
    if err != nil {
        return err
    }
    defer source.Close()

    destination, err := os.Create(dst)
    if err != nil {
        return err
    }
    defer destination.Close()

    _, err = io.Copy(destination, source)
    if err != nil {
        return err
    }

    err = os.Chmod(dst, 0544)
    return err
}

func cgroup2Filter(info *mountinfo.Info) (bool, bool) {
    if (info.FSType == "cgroup2") {
        return false, false
    }
    return true, false
}

func cgroup2Mount() (string, error) {
    mounts, err := mountinfo.GetMounts(cgroup2Filter)
    if (err == nil) {
        if (len(mounts) == 0) {
            return "", fmt.Errorf("No cgroup2 mount point detected")
        }
        if (len(mounts) > 1) {
            fmt.Println("Multiple cgroup2 mounts detected, using the first one...")
        }
        return mounts[0].Mountpoint, nil
    } else {
        return "", err
    }
}

func main() {
    fmt.Println("Sockmap daemon process has started...")

    mount, err := cgroup2Mount()
    if (err == nil) {
        fmt.Printf("Cgroup2 mount point: %s\n", mount)
    } else {
        fmt.Printf("Trying to mount cgroup2...")

        os.MkdirAll("/var/run/sk-accelerate/cgroupv2", os.ModePerm)

        cmd := exec.Command("/bin/mount", "-t", "cgroup2", "none", "/var/run/sk-accelerate/cgroupv2")
        err := cmd.Run()
        if err != nil {
            log.Fatal(err)
        }
        mount = "/var/run/sk-accelerate/cgroupv2"
        fmt.Printf("Done\n")
    }

    fmt.Print("Copying files...")
    // Copy the required files to host machine
    os.MkdirAll("/opt/sockmap", os.ModePerm)
    fileCopy("/root/bin/bpftool", "/opt/sockmap/bpftool")
    fileCopy("/root/bin/sockmap_redir.o", "/opt/sockmap/sockmap_redir.o")
    fileCopy("/root/bin/sockops.o", "/opt/sockmap/sockops.o")
    fmt.Println("Done")

    // Load and attach ebpf program
    fmt.Print("Loading sockops program...")
    cmd := exec.Command("/opt/sockmap/bpftool", "prog", "load", "/opt/sockmap/sockops.o", "/sys/fs/bpf/sockop")
    err = cmd.Run()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Done")

    fmt.Print("Attaching sockops program...")
    cmd = exec.Command("/opt/sockmap/bpftool", "cgroup", "attach", mount, "sock_ops", "pinned", "/sys/fs/bpf/sockop")
    err = cmd.Run()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Done")

    fmt.Print("Loading sockmaps program...")
    cmd = exec.Command("/opt/sockmap/bpftool", "prog", "load", "/opt/sockmap/sockmap_redir.o", "/sys/fs/bpf/bpf_redir", "map", "name", "sock_ops_map", "pinned", "/sys/fs/bpf/sock_ops_map")
    err = cmd.Run()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Done")

    fmt.Print("Attaching sockmap program...")
    cmd = exec.Command("/opt/sockmap/bpftool", "prog", "attach", "pinned", "/sys/fs/bpf/bpf_redir", "msg_verdict", "pinned", "/sys/fs/bpf/sock_ops_map")
    err = cmd.Run()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Done")

    c := make(chan os.Signal)
    signal.Notify(c, syscall.SIGTERM)
    go func() {
        <- c
        cleanup()
        os.Exit(0)
    }()

    StartController()


    // TODO: need an API server to load/unload the sockmap program
    for {
        time.Sleep(time.Duration(1<<63 - 1))
    }
}
