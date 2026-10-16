#!/system/bin/sh
# ============================================================
#  discord_dpi - Magisk service.sh (v4 - fail-open surum)
#  nfqws (NFQUEUE 200) + dnsproxy (DoH :5335)
#  nfqttl (nfqttli/nfqttlo, 6464) ELLENMEZ.
#  v4: IPv6 mudahalesi yok; DNS ve DPI canli test ile dogrulanir,
#  test gecmezse kurallar otomatik geri alinir (internet korunur).
# ============================================================

PATH=/system/bin:/system/xbin:$PATH

MODDIR=${0%/*}
BINDIR="$MODDIR/system/bin"
FAKEDIR="$MODDIR/fake"
RUNDIR="$MODDIR/run"
LOGDIR="$MODDIR/log"

NFQWS="$BINDIR/nfqws"
DNSPROXY="$BINDIR/dnsproxy"
LOGF="$LOGDIR/service.log"

QNUM=200
DNS_PORT=5335
MARK="0x40000000/0x40000000"
TCP_PORTS="80,443"
UDP_PORTS="443,19294:19344,3478:3481,50000:50099"
WAN_IFACES="rmnet_data+ rmnet+ ccmni+"

mkdir -p "$RUNDIR" "$LOGDIR"
DNSV6=0
DNSBACKOFF=0
DPIBACKOFF=0

log()
{
    echo "$(date +%Y-%m-%d_%H:%M:%S) $*" >> "$LOGF"
}

have()
{
    command -v "$1" >/dev/null 2>&1
}

kill_if_ours()
{
    _pid="$1"
    _name="$2"
    _file="$3"
    if [ -n "$_pid" ] && [ -d "/proc/$_pid" ] && grep -q "$_name" "/proc/$_pid/cmdline" 2>/dev/null; then
        kill "$_pid" 2>/dev/null
    fi
    rm -f "$_file"
}

kill_nfqws()
{
    if [ -f "$RUNDIR/nfqws.pid" ]; then
        kill_if_ours "$(cat "$RUNDIR/nfqws.pid" 2>/dev/null)" "nfqws" "$RUNDIR/nfqws.pid"
    fi
}

kill_dns()
{
    if [ -f "$RUNDIR/dnsproxy.pid" ]; then
        kill_if_ours "$(cat "$RUNDIR/dnsproxy.pid" 2>/dev/null)" "dnsproxy" "$RUNDIR/dnsproxy.pid"
    fi
}

kill_procs()
{
    kill_nfqws
    kill_dns
}

# ---------- canli testler (fail-open kapilari) ----------
probe_dns()
{
    if have nc; then
        printf '\022\064\001\000\000\001\000\000\000\000\000\000\007example\003com\000\000\001\000\001' | nc -u -w 4 127.0.0.1 $DNS_PORT > "$RUNDIR/dnsprobe.bin" 2>/dev/null
        size=$(wc -c < "$RUNDIR/dnsprobe.bin" 2>/dev/null)
        if [ -n "$size" ] && [ "$size" -ge 28 ]; then
            return 0
        fi
        return 1
    fi
    if have ping; then
        ping -c 1 -W 3 www.google.com 2>&1 | grep -Eq '\(([0-9]{1,3}\.){3}[0-9]{1,3}\)' && return 0
        return 1
    fi
    return 0
}

dns_gate()
{
    i=0
    while [ $i -lt 3 ]; do
        probe_dns && return 0
        i=$((i+1))
        sleep 3
    done
    return 1
}

probe_tcp()
{
    have nc || return 0
    nc -w 4 1.1.1.1 443 < /dev/null > /dev/null 2>&1 && return 0
    nc -w 4 8.8.8.8 443 < /dev/null > /dev/null 2>&1 && return 0
    return 1
}

tcp_gate()
{
    i=0
    while [ $i -lt 3 ]; do
        probe_tcp && return 0
        i=$((i+1))
        sleep 3
    done
    return 1
}

# ---------- temizlik (yalnizca kendi kurallarimiz + eski surum kalintilari) ----------
cleanup_dns_rules()
{
    while iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT 2>/dev/null; do :; done
    while iptables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports $DNS_PORT 2>/dev/null; do :; done
    while iptables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT 2>/dev/null; do :; done
    while iptables -t nat -D OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports $DNS_PORT 2>/dev/null; do :; done
    while ip6tables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT 2>/dev/null; do :; done
    while ip6tables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports $DNS_PORT 2>/dev/null; do :; done
    while ip6tables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT 2>/dev/null; do :; done
    while ip6tables -t nat -D OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports $DNS_PORT 2>/dev/null; do :; done
    while ip6tables -D INPUT -p udp --dport 53 -j REJECT 2>/dev/null; do :; done
    while ip6tables -D INPUT -p tcp --dport 53 -j REJECT 2>/dev/null; do :; done
    while ip6tables -D OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null; do :; done
    while ip6tables -D OUTPUT -p tcp --dport 53 -j REJECT 2>/dev/null; do :; done
    while ip6tables -D FORWARD -p udp --dport 53 -j REJECT 2>/dev/null; do :; done
    while ip6tables -D FORWARD -p tcp --dport 53 -j REJECT 2>/dev/null; do :; done
}

cleanup_dpi_rules()
{
    while iptables -t mangle -D OUTPUT -j DPI_OUT_TCP 2>/dev/null; do :; done
    while iptables -t mangle -D OUTPUT -j DPI_OUT_UDP 2>/dev/null; do :; done
    while iptables -t mangle -D FORWARD -j DPI_FWD_TCP 2>/dev/null; do :; done
    while iptables -t mangle -D FORWARD -j DPI_FWD_UDP 2>/dev/null; do :; done
    iptables -t mangle -F DPI_OUT_TCP 2>/dev/null
    iptables -t mangle -F DPI_OUT_UDP 2>/dev/null
    iptables -t mangle -F DPI_FWD_TCP 2>/dev/null
    iptables -t mangle -F DPI_FWD_UDP 2>/dev/null
    iptables -t mangle -X DPI_OUT_TCP 2>/dev/null
    iptables -t mangle -X DPI_OUT_UDP 2>/dev/null
    iptables -t mangle -X DPI_FWD_TCP 2>/dev/null
    iptables -t mangle -X DPI_FWD_UDP 2>/dev/null

    while iptables -t mangle -D POSTROUTING -j DPI_TR_TCP 2>/dev/null; do :; done
    while iptables -t mangle -D POSTROUTING -j DPI_TR_UDP 2>/dev/null; do :; done
    iptables -t mangle -F DPI_TR_TCP 2>/dev/null
    iptables -t mangle -F DPI_TR_UDP 2>/dev/null
    iptables -t mangle -X DPI_TR_TCP 2>/dev/null
    iptables -t mangle -X DPI_TR_UDP 2>/dev/null

    while ip6tables -t mangle -D POSTROUTING -j DPI_TR6_TCP 2>/dev/null; do :; done
    while ip6tables -t mangle -D POSTROUTING -j DPI_TR6_UDP 2>/dev/null; do :; done
    ip6tables -t mangle -F DPI_TR6_TCP 2>/dev/null
    ip6tables -t mangle -F DPI_TR6_UDP 2>/dev/null
    ip6tables -t mangle -X DPI_TR6_TCP 2>/dev/null
    ip6tables -t mangle -X DPI_TR6_UDP 2>/dev/null

    while iptables -t mangle -D POSTROUTING -m mark --mark $MARK -j CONNMARK --or-mark 0x40000000 2>/dev/null; do :; done
    while iptables -D INPUT -p icmp --icmp-type time-exceeded -m connmark --mark $MARK -j DROP 2>/dev/null; do :; done
    while iptables -D FORWARD -p icmp --icmp-type time-exceeded -m connmark --mark $MARK -j DROP 2>/dev/null; do :; done

    for IF in $WAN_IFACES; do
        while iptables -t mangle -D POSTROUTING -o $IF -j TTL --ttl-set 64 2>/dev/null; do :; done
        while iptables -t mangle -D POSTROUTING -m mark ! --mark $MARK -o $IF -j TTL --ttl-set 64 2>/dev/null; do :; done
        while ip6tables -t mangle -D POSTROUTING -o $IF -j HL --hl-set 64 2>/dev/null; do :; done
        while ip6tables -t mangle -D POSTROUTING -m mark ! --mark $MARK -o $IF -j HL --hl-set 64 2>/dev/null; do :; done
    done
}

# ---------- dnsproxy (DoH) ----------
start_dns()
{
    [ -x "$DNSPROXY" ] || { log "HATA: dnsproxy bulunamadi ($DNSPROXY)"; return 1; }
    : > "$LOGDIR/dnsproxy.log"

    # Upstream'ler IP-literal DoH'dir ve bootstrap kullanilmaz: dnsproxy
    # hicbir asamada port 53'e paket gondermez -> kendi REDIRECT kuraliyla
    # donguye giremez.
    "$DNSPROXY" -l 0.0.0.0 -p $DNS_PORT \
        -u https://1.1.1.1/dns-query \
        -u https://9.9.9.9/dns-query \
        -f https://8.8.8.8/dns-query \
        --cache --cache-size=4194304 --upstream-mode=parallel --timeout=5s \
        >> "$LOGDIR/dnsproxy.log" 2>&1 &
    echo $! > "$RUNDIR/dnsproxy.pid"
    sleep 2
    if kill -0 "$(cat "$RUNDIR/dnsproxy.pid")" 2>/dev/null; then
        log "dnsproxy calisiyor (port $DNS_PORT)"
        return 0
    fi
    log "HATA: dnsproxy baslatilamadi ($LOGDIR/dnsproxy.log)"
    return 1
}

# ---------- nfqws ----------
start_nfqws()
{
    [ -x "$NFQWS" ] || { log "HATA: nfqws bulunamadi ($NFQWS)"; return 1; }
    : > "$LOGDIR/nfqws.log"
    chmod 666 "$LOGDIR/nfqws.log" 2>/dev/null
    : > "$RUNDIR/nfqws.pid"
    chmod 666 "$RUNDIR/nfqws.pid" 2>/dev/null

    P_DISCORD="--filter-udp=19294-19344,50000-50099 --filter-l7=discord --dpi-desync=fake --dpi-desync-repeats=2 --dpi-desync-ttl=4"
    if [ -f "$FAKEDIR/discord-ip-discovery-with-port.bin" ]; then
        P_DISCORD="$P_DISCORD --dpi-desync-fake-discord=@$FAKEDIR/discord-ip-discovery-with-port.bin"
    fi

    P_STUN="--filter-udp=* --filter-l7=stun --dpi-desync=fake --dpi-desync-repeats=2 --dpi-desync-ttl=4"
    if [ -f "$FAKEDIR/stun.bin" ]; then
        P_STUN="$P_STUN --dpi-desync-fake-stun=@$FAKEDIR/stun.bin"
    fi

    "$NFQWS" --qnum=$QNUM --daemon --pidfile="$RUNDIR/nfqws.pid" \
        --uid=1:3003 --debug=@$LOGDIR/nfqws.log \
        --filter-tcp=80 --dpi-desync=fake,multisplit --dpi-desync-split-pos=method+2 --dpi-desync-fooling=md5sig --dpi-desync-ttl=64 --new \
        --filter-tcp=443 --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq,md5sig --dpi-desync-ttl=64 --new \
        --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-ttl=4 --new \
        $P_DISCORD --new \
        $P_STUN >> "$LOGDIR/nfqws.log" 2>&1
    sleep 2
    if kill -0 "$(cat "$RUNDIR/nfqws.pid" 2>/dev/null)" 2>/dev/null; then
        log "nfqws calisiyor (qnum $QNUM, uid 1:3003)"
        return 0
    fi
    log "HATA: nfqws baslatilamadi ($LOGDIR/nfqws.log)"
    return 1
}

# ---------- DNS yonlendirme ----------
add_dns_rules()
{
    iptables -t nat -I PREROUTING 1 -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT
    iptables -t nat -I PREROUTING 1 -p tcp --dport 53 -j REDIRECT --to-ports $DNS_PORT
    iptables -t nat -I OUTPUT 1 -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT
    iptables -t nat -I OUTPUT 1 -p tcp --dport 53 -j REDIRECT --to-ports $DNS_PORT
    log "DNS yonlendirme kurallari eklendi (53 -> $DNS_PORT)"
}

# ---------- DPI kurallari (yerel=OUTPUT uid0 haric, hotspot=FORWARD) ----------
add_dpi_rules()
{
    iptables -t mangle -N DPI_OUT_TCP 2>/dev/null
    iptables -t mangle -N DPI_OUT_UDP 2>/dev/null
    iptables -t mangle -N DPI_FWD_TCP 2>/dev/null
    iptables -t mangle -N DPI_FWD_UDP 2>/dev/null

    for CH in DPI_OUT_TCP DPI_FWD_TCP; do
        iptables -t mangle -A $CH -d 127.0.0.0/8 -j RETURN
        iptables -t mangle -A $CH -d 10.0.0.0/8 -j RETURN
        iptables -t mangle -A $CH -d 172.16.0.0/12 -j RETURN
        iptables -t mangle -A $CH -d 192.168.0.0/16 -j RETURN
        iptables -t mangle -A $CH -d 100.64.0.0/10 -j RETURN
    done
    for CH in DPI_OUT_UDP DPI_FWD_UDP; do
        iptables -t mangle -A $CH -d 127.0.0.0/8 -j RETURN
        iptables -t mangle -A $CH -d 10.0.0.0/8 -j RETURN
        iptables -t mangle -A $CH -d 172.16.0.0/12 -j RETURN
        iptables -t mangle -A $CH -d 192.168.0.0/16 -j RETURN
        iptables -t mangle -A $CH -d 100.64.0.0/10 -j RETURN
    done

    CB=""
    if iptables -m connbytes --help >/dev/null 2>&1; then
        CB="-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9"
    fi

    if ! iptables -t mangle -A DPI_OUT_TCP -m mark ! --mark $MARK -m owner ! --uid-owner 0 -p tcp -m multiport --dports $TCP_PORTS $CB -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null; then
        CB=""
        log "UYARI: connbytes kullanilamadi, OUTPUT TCP limitsiz"
        iptables -t mangle -A DPI_OUT_TCP -m mark ! --mark $MARK -m owner ! --uid-owner 0 -p tcp -m multiport --dports $TCP_PORTS -j NFQUEUE --queue-num $QNUM --queue-bypass
    fi

    if ! iptables -t mangle -A DPI_FWD_TCP -m mark ! --mark $MARK -p tcp -m multiport --dports $TCP_PORTS $CB -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null; then
        log "UYARI: FORWARD TCP kural connbytes'siz denendi"
        iptables -t mangle -A DPI_FWD_TCP -m mark ! --mark $MARK -p tcp -m multiport --dports $TCP_PORTS -j NFQUEUE --queue-num $QNUM --queue-bypass
    fi

    if ! iptables -t mangle -A DPI_OUT_UDP -m mark ! --mark $MARK -m owner ! --uid-owner 0 -p udp -m multiport --dports $UDP_PORTS $CB -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null; then
        log "UYARI: OUTPUT UDP kural connbytes'siz denendi"
        iptables -t mangle -A DPI_OUT_UDP -m mark ! --mark $MARK -m owner ! --uid-owner 0 -p udp -m multiport --dports $UDP_PORTS -j NFQUEUE --queue-num $QNUM --queue-bypass
    fi

    if ! iptables -t mangle -A DPI_FWD_UDP -m mark ! --mark $MARK -p udp -m multiport --dports $UDP_PORTS $CB -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null; then
        log "UYARI: FORWARD UDP kural connbytes'siz denendi"
        iptables -t mangle -A DPI_FWD_UDP -m mark ! --mark $MARK -p udp -m multiport --dports $UDP_PORTS -j NFQUEUE --queue-num $QNUM --queue-bypass
    fi

    iptables -t mangle -A OUTPUT -j DPI_OUT_TCP
    iptables -t mangle -A OUTPUT -j DPI_OUT_UDP
    iptables -t mangle -A FORWARD -j DPI_FWD_TCP
    iptables -t mangle -A FORWARD -j DPI_FWD_UDP

    if iptables -m connmark --help >/dev/null 2>&1; then
        iptables -t mangle -A POSTROUTING -m mark --mark $MARK -j CONNMARK --or-mark 0x40000000 2>/dev/null
        iptables -A INPUT -p icmp --icmp-type time-exceeded -m connmark --mark $MARK -j DROP 2>/dev/null
        iptables -A FORWARD -p icmp --icmp-type time-exceeded -m connmark --mark $MARK -j DROP 2>/dev/null
    fi

    # TTL emniyet kemeri: yalnizca marksiz GERCEK paketler 64'e sabitlenir.
    for IF in $WAN_IFACES; do
        iptables -t mangle -A POSTROUTING -m mark ! --mark $MARK -o $IF -j TTL --ttl-set 64 2>/dev/null || log "UYARI: TTL hedefi eklenemedi ($IF)"
    done

    log "DPI kurallari eklendi (OUTPUT uid0-haric + FORWARD, NFQUEUE $QNUM)"
}

# ---------- acilis ----------
main()
{
    while [ "$(/system/bin/getprop sys.boot_completed)" != "1" ]; do
        sleep 2
    done
    sleep 5

    rm -f "$RUNDIR/stop"
    chmod 755 "$NFQWS" "$DNSPROXY" 2>/dev/null

    i=0
    while [ $i -lt 30 ]; do
        ip route show default 2>/dev/null | grep -q default && break
        i=$((i+1))
        sleep 2
    done

    kill_procs
    cleanup_dns_rules
    cleanup_dpi_rules

    if start_dns; then
        add_dns_rules
        if dns_gate; then
            log "DNS testi BASARILI"
        else
            log "HATA: DNS testi BASARISIZ -> DNS yonlendirme geri alindi (internet korunur)"
            cleanup_dns_rules
            kill_dns
            DNSBACKOFF=10
        fi
    fi

    if start_nfqws; then
        add_dpi_rules
        if tcp_gate; then
            log "TCP testi BASARILI"
        else
            log "HATA: TCP testi BASARISIZ -> DPI kurallari geri alindi (internet korunur)"
            cleanup_dpi_rules
            kill_nfqws
            DPIBACKOFF=10
        fi
    fi

    log "baslatma tamamlandi"
}

# ---------- bekci ----------
check_dpi()
{
    [ -x "$NFQWS" ] || return

    alive=0
    kill -0 "$(cat "$RUNDIR/nfqws.pid" 2>/dev/null)" 2>/dev/null && alive=1

    if [ "$alive" = "0" ]; then
        log "nfqws durmus, yeniden baslatiliyor"
        if ! start_nfqws; then
            DPIBACKOFF=10
            return
        fi
    fi

    if ! iptables -t mangle -C OUTPUT -j DPI_OUT_TCP 2>/dev/null; then
        log "DPI kurallari eksik, yeniden ekleniyor"
        cleanup_dpi_rules
        add_dpi_rules
        if ! tcp_gate; then
            log "HATA: TCP testi basarisiz, DPI kurallari geri alindi"
            cleanup_dpi_rules
            kill_nfqws
            DPIBACKOFF=10
        fi
    fi
}

check_dns()
{
    [ -x "$DNSPROXY" ] || return

    alive=0
    kill -0 "$(cat "$RUNDIR/dnsproxy.pid" 2>/dev/null)" 2>/dev/null && alive=1

    if [ "$alive" = "0" ]; then
        log "dnsproxy durmus, yeniden baslatiliyor"
        if ! start_dns; then
            log "dnsproxy tekrar baslamadi, DNS yonlendirme kaldiriliyor"
            cleanup_dns_rules
            DNSBACKOFF=10
            return
        fi
    fi

    if ! iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT 2>/dev/null; then
        log "DNS kurallari eksik, yeniden ekleniyor"
        cleanup_dns_rules
        add_dns_rules
        if ! dns_gate; then
            log "HATA: DNS testi basarisiz, yonlendirme geri alindi"
            cleanup_dns_rules
            kill_dns
            DNSBACKOFF=10
        fi
    fi
}

watchdog()
{
    n=0
    while true; do
        if [ -f "$RUNDIR/stop" ]; then
            log "stop bayragi goruldu, watchdog cikiyor"
            exit 0
        fi
        sleep 30
        n=$((n+1))
        if [ $DNSBACKOFF -gt 0 ]; then
            DNSBACKOFF=$((DNSBACKOFF-1))
        else
            check_dns
        fi
        if [ $DPIBACKOFF -gt 0 ]; then
            DPIBACKOFF=$((DPIBACKOFF-1))
        else
            check_dpi
        fi
    done
}

case "$1" in
    bg)
        main
        watchdog
        ;;
    *)
        : > "$LOGF"
        rm -f "$RUNDIR/stop"
        sh "$MODDIR/service.sh" bg &
        echo $! > "$RUNDIR/service.pid"
        exit 0
        ;;
esac
