package main

import (
    "fmt"
    "net"
    "errors"
    "os"
    "os/signal"
    "time"
    "syscall"
    "runtime"
    "flag"
    "golang.org/x/net/ipv4"
    "encoding/binary"
)

type stats struct {
    Packets uint64
    Bytes uint64
    RTT uint64
}
type addrList []string
type options struct {
    saddrs      addrList
    caddrs      addrList
    srvSrtPort  int
    cliSrtPort  int
    isServer    bool
    threads     int
}

var shouldRun bool

func (i *addrList) String() string {
    return fmt.Sprintf("%v", []string(*i))
}

func (al *addrList) Set(value string) error {
    *al = append(*al, value)
    return nil
}

func fmthuman(val float64) string {
    idx := 0
    sufix := []string{" ", "K", "M", "G", "T", "P"}
    for ;val > 1024; {
        val /= 1024
        idx += 1
    }
    return fmt.Sprintf("%d %s", int(val), sufix[idx])

}

func receiver(src_ip string, src_port int, l_stats *stats) {
    var i uint64
    var b uint64
    var batchSize uint64

    batchSize = 1024
    msgs := make([]ipv4.Message, batchSize)

    for k := range msgs {
        msgs[k].Buffers = [][]byte{make([]byte, 8)}
    }

    addr := net.UDPAddr{
        Port: src_port,
        IP:   net.ParseIP(src_ip),
    }

    conn, err := net.ListenUDP("udp", &addr)
    if err != nil {
        panic(fmt.Sprintf("Could not bind to %v: %v", src_port, err))
    }
    pconn := ipv4.NewPacketConn(conn)

    conn.SetDeadline(time.Now())
    for ;shouldRun; {
        cnt, err := pconn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
        if errors.Is(err, os.ErrDeadlineExceeded) {
            conn.SetDeadline(time.Now().Add(time.Second * 5))
            continue
        } else if err != nil {
            break
        }
        if cnt == 0 {
            continue
        }

        i += uint64(cnt)
        b += uint64(cnt * 8)

        l_stats.Packets = i
        l_stats.Bytes = b

        conn.SetDeadline(time.Now().Add(time.Second * 5))
        _, err = pconn.WriteBatch(msgs[0:cnt], 0)
        if err != nil {
            break
        }
    }

    conn.Close()
}

func sender(src_ip string, src_port int, dst_ip string, dst_port int, l_stats *stats) {
    var i uint64
    var b uint64
    var r uint64
    var seen_time int64
    data := make([]byte, 8)

    daddr := net.UDPAddr{
        IP: net.ParseIP(dst_ip),
        Port: dst_port,
    }
    saddr := net.UDPAddr{
        IP: net.ParseIP(src_ip),
        Port: src_port,
    }

    conn, err := net.DialUDP("udp", &saddr, &daddr)

    if err != nil {
        panic(fmt.Sprintf("Could not bind to %v: %v", dst_port, err))
    }

    defer conn.Close()
    conn.SetDeadline(time.Now())

    for ;shouldRun; {
        n, _, err := conn.ReadFromUDP(data)
        if errors.Is(err, os.ErrDeadlineExceeded) {
            goto SEND
        } else if err != nil {
            break
        } else if n != 8 {
            continue
        }
        i += 1
        b += 8
        seen_time, _ = binary.Varint(data)
        r += uint64(time.Now().UnixMicro() - seen_time)
        l_stats.Bytes = b
        l_stats.Packets = i
        l_stats.RTT = r

SEND:
        conn.SetDeadline(time.Now().Add(time.Second * 5))
        binary.PutVarint(data, time.Now().UnixMicro())
        _, err = conn.Write(data)
    }
}

func launcher(opts *options) {
    var Pps uint64
    var Bps uint64
    var Rtt uint64
    var lastPps uint64
    var lastBps uint64
    var lastRtt uint64
    var calcPps float64
    var calcBps float64
    var calcRtt float64
    var totalPps uint64
    var totalBps uint64
    var totalRtt uint64
    var runners int


    if opts.threads == 0 {
        switch cntCPU := runtime.NumCPU(); {
        case cntCPU < 3:
            runners = 1
        case cntCPU < 12:
            runners = cntCPU >> 1
        default:
            runners = cntCPU >> 2
        }
    } else {
        runners = opts.threads
    }

    g_stats := make([]stats, runners)

    for i:=0;i<runners;i++ {
        if opts.isServer {
            go receiver(opts.saddrs[i % len(opts.saddrs)],
                        opts.srvSrtPort + i,
                        &g_stats[i])
        } else {
            go sender(opts.caddrs[i % len(opts.caddrs)],
                      opts.cliSrtPort + i,
                      opts.saddrs[i % len(opts.saddrs)],
                      opts.srvSrtPort + i,
                      &g_stats[i])
        }
    }

    for ;shouldRun; {
        Pps = 0
        Bps = 0
        Rtt = 0
        for h:=0;h<runners;h++ {
            Pps += g_stats[h].Packets
            Bps += g_stats[h].Bytes
            Rtt += g_stats[h].RTT
        }
        totalPps += Pps
        totalBps += Bps
        calcPps = float64(Pps - lastPps) * 1000 / 800
        calcBps = float64(Bps - lastBps) * 1000 / 800

        if opts.isServer {
            fmt.Printf("\r%spps %sbps           ", fmthuman(calcPps), fmthuman(calcBps*8))
        } else {
            totalRtt += Rtt
            calcRtt = float64(Rtt - lastRtt) / float64(Pps - lastPps)
            lastRtt = Rtt
            fmt.Printf("\r%spps %sbps %0.02f us RTT        ", fmthuman(calcPps), fmthuman(calcBps*8), calcRtt)
        }

        lastPps = Pps
        lastBps = Bps
        time.Sleep(time.Millisecond * 800)
    }
    fmt.Printf("\n")
}

func Init() {
    c := make(chan os.Signal)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        shouldRun = false
    } ()
}

func main() {
    shouldRun = true
    var opts options

    flag.Var(&opts.saddrs, "saddr", "The server IP.")
    flag.Var(&opts.caddrs, "caddr", "The client IP.")
    flag.BoolVar(&opts.isServer, "s", false, "Act as a server")
    flag.IntVar(&opts.srvSrtPort, "p", 1330, "Initial server port")
    flag.IntVar(&opts.cliSrtPort, "d", 1330, "Initial client port")
    flag.IntVar(&opts.threads, "threads", 0, "number of threds")

    flag.Parse()

    Init()

    if len(opts.saddrs) == 0 {
        opts.saddrs = append(opts.saddrs, "0.0.0.0")
    }
    if len(opts.caddrs) == 0 {
        opts.caddrs = append(opts.caddrs, "127.0.0.1")
    }
    launcher(&opts)
}
