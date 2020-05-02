package main

import (
	"context"
	"errors"
	"github.com/BurntSushi/toml"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// 不可以以报文之间的间隔时间作为 timer 来发送
// 这样单个报文的抖动会导致整体偏移
// 如果使用绝对时间，是可以弥补单个报文的抖动的

type Config struct {
	PcapFilePath string
	SourceAddr   string
	DestAddr     string
}

type DelayedPacket struct {
	Since   time.Duration
	Payload []byte
}

type ReplayCtl struct {
	Ctx        context.Context
	StartTime  time.Time
	Timer      *time.Timer
	Writer     io.Writer
	WriteCount uint64
}

func (ctl *ReplayCtl) DelayWrite(ctx context.Context, payload []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-ctl.Timer.C:
		return ctl.Writer.Write(payload)
	}
}

func (ctl *ReplayCtl) ReplayPacket(ctx context.Context, pkt *DelayedPacket) {
	if ctl.StartTime.IsZero() {
		ctl.StartTime = time.Now()
	}
	expectWriteTime := ctl.StartTime.Add(pkt.Since)
	delay := time.Until(expectWriteTime)
	if delay < 0 {
		delay = 0
	}
	ctl.Timer.Reset(delay)
	// sub some time for golang runtime take
	// delay = delay.Truncate(50 * time.Microsecond)
	if delay > 0 {
		_, _ = ctl.DelayWrite(ctx, pkt.Payload)
	} else {
		_, _ = ctl.Writer.Write(pkt.Payload)
	}
	ctl.WriteCount += 1
	log.Printf("%-7v write takeTime %-17v/expect takeTime %-17v", ctl.WriteCount, time.Since(ctl.StartTime), pkt.Since)
}

func replayPackets(ctx context.Context, writer io.Writer, pktCh chan *DelayedPacket) {
	ctl := &ReplayCtl{
		Writer: writer,
		Timer:  time.NewTimer(0),
	}
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case pkt, more := <-pktCh:
			if !more {
				break loop
			}
			ctl.ReplayPacket(ctx, pkt)
		}
	}
}

func setupSignal(ctx context.Context, cancel context.CancelFunc) {
	ch := make(chan os.Signal, 3)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	select {
	case <-ctx.Done():
	case v := <-ch:
		log.Printf("got signal %v, exit", v)
		cancel()
	}
}

func parsePackets(ctx context.Context, source *gopacket.PacketSource, pktCh chan *DelayedPacket) {
	fstPacketTime := time.Time{}
	writeCount := 0
	startTime := time.Now()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		default:
		}
		pkt, err := source.NextPacket()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break loop
			}
			continue
		}
		time0 := pkt.Metadata().Timestamp
		layer := pkt.ApplicationLayer()
		if layer == nil {
			continue
		}
		if fstPacketTime.IsZero() {
			fstPacketTime = time0
		}
		newPkt := &DelayedPacket{
			Since:   time0.Sub(fstPacketTime),
			Payload: layer.Payload(),
		}
		select {
		case <-ctx.Done():
			break loop
		case pktCh <- newPkt:
			writeCount += 1
		}
	}
	close(pktCh)
	log.Printf("packets all enqueue count %v, takeTime %v", writeCount, time.Since(startTime))
}

func entry(conf *Config, conn net.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	fpath := conf.PcapFilePath
	log.Printf("read from `%v`", fpath)
	handle, err := pcap.OpenOffline(fpath)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		setupSignal(ctx, cancel)
	}()
	pktCh := make(chan *DelayedPacket, 50*1000)
	wg.Add(1)
	go func() {
		replayPackets(ctx, conn, pktCh)
		wg.Done()
	}()
	start := time.Now()
	log.Printf("start write packets")
	parsePackets(ctx, source, pktCh)
	wg.Wait()
	log.Printf("end write packets, takeTime %v", time.Since(start))
	cancel()
}

func setupWriter(conf *Config) net.Conn {
	toAddr := conf.DestAddr
	raddr, err := net.ResolveUDPAddr("udp", toAddr)
	if err != nil {
		log.Fatal(err)
	}
	var laddr *net.UDPAddr
	if conf.SourceAddr != "" {
		laddr, err = net.ResolveUDPAddr("udp", conf.SourceAddr)
	}
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		log.Fatal(err)
	}
	return conn
}

func main() {
	log.SetOutput(os.Stdout)
	conf := &Config{}
	exePath, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	confPath := filepath.Join(filepath.Dir(exePath), "config.toml")
	_, err = toml.DecodeFile(confPath, conf)
	if err != nil {
		log.Fatal(err)
	}
	conn := setupWriter(conf)
	entry(conf, conn)
	log.Printf("main exit")
}
