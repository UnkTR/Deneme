#!/system/bin/sh
# ============================================================
#  discord_dpi - Magisk service.sh (v6)
#  Motor  : zapret2 / nfqws2 (Android ARM64)
#  Strateji (ISS'de test edilip CALISTI):
#    --payload=tls_client_hello
#    --lua-desync=tcpseg:pos=0,1:ip_id=rnd:repeats=1
#  DNS    : dnsproxy (DoH :5335)
#  nfqttl ile UYUMLU: onun zincirlerine/kuyruguna dokunulmaz.
#  IPv6 mudahalesi YOK, TTL kemeri YOK, otomatik test YOK.
# ============================================================

PATH=/system/bin:/system/xbin:$PATH

MODDIR=${0%/*}
BINDIR="$MODDIR/system/bin"
LUADIR="$MODDIR/lua"
RUNDIR="$MODDIR/run"
LOGDIR="$MODDIR/log"

NFQWS2="$BINDIR/nfqws2"
DNSPROXY="$BINDIR/dnsproxy"
LOGF="$LOGDIR/service.log"

QNUM=200
DNS_PORT=5335
MARK="0x40000000/0x40000000"
TCP_PORTS="80,443"
WAN_IFACES="rmnet_data+ rmnet+ ccmni+"

mkdir -p "$RUNDIR" "$LOGDIR"

log()
{
    echo "$(date +%Y-%m-%d_%H:%M:%S) $*" >> "$LOGF"
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
    if [ -f "$RUNDIR/nfqws2.pid" ]; then
        kill_if_ours "$(cat "$RUNDIR/nfqws2.pid" 2>/dev/null)" "nfqws2" "$RUNDIR/nfqws2.pid"
    fi
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

# ---------- temizlik: eski surumlerin biraktigi her seyi kaldirir ----------
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
    # v5/v6 zinciri
    while iptables -t mangle -D POSTROUTING -j DPI_TR_TCP 2>/dev/null; do :; done
    while iptables -t mangle -D POSTROUTING -j DPI_TR_UDP 2>/dev/null; do :; done
    iptables -t mangle -F DPI_TR_TCP 2>/dev/null
    iptables -t mangle -F DPI_TR_UDP 2>/dev/null
    iptables -t mangle -X DPI_TR_TCP 2>/dev/null
    iptables -t mangle -X DPI_TR_UDP 2>/dev/null

    # v4 zincirleri
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

    # v3 ipv6 zincirleri
    while ip6tables -t mangle -D POSTROUTING -j DPI_TR6_TCP 2>/dev/null; do :; done
    while ip6tables -t mangle -D POSTROUTING -j DPI_TR6_UDP 2>/dev/null; do :; done
    ip6tables -t mangle -F DPI_TR6_TCP 2>/dev/null
    ip6tables -t mangle -F DPI_TR6_UDP 2>/dev/null
    ip6tables -t mangle -X DPI_TR6_TCP 2>/dev/null
    ip6tables -t mangle -X DPI_TR6_UDP 2>/dev/null

    # eski connmark/icmp + TTL/HL kemerleri
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

# ---------- dnsproxy ----------
start_dns()
{
    [ -x "$DNSPROXY" ] || { log "HATA: dnsproxy bulunamadi"; return 1; }
    : > "$LOGDIR/dnsproxy.log"

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

# ---------- nfqws2 (zapret2) ----------
start_nfqws2()
{
    [ -x "$NFQWS2" ] || { log "HATA: nfqws2 bulunamadi"; return 1; }
    [ -f "$LUADIR/zapret-lib.lua" ] || { log "HATA: lua dosyalari eksik"; return 1; }
    chmod 755 "$LUADIR" 2>/dev/null
    chmod 644 "$LUADIR"/*.lua 2>/dev/null
    : > "$LOGDIR/nfqws2.log"
    chmod 666 "$LOGDIR/nfqws2.log" 2>/dev/null
    : > "$RUNDIR/nfqws2.pid"
    chmod 666 "$RUNDIR/nfqws2.pid" 2>/dev/null

    "$NFQWS2" --qnum=$QNUM --daemon --pidfile="$RUNDIR/nfqws2.pid" \
        --uid=1:3003 --fwmark=0x40000000 --debug=@$LOGDIR/nfqws2.log \
        --lua-init=@"$LUADIR/zapret-lib.lua" \
        --lua-init=@"$LUADIR/zapret-antidpi.lua" \
        --payload=tls_client_hello \
        --lua-desync=tcpseg:pos=0,1:ip_id=rnd:repeats=1 \
        >> "$LOGDIR/nfqws2.log" 2>&1
    sleep 2
    if kill -0 "$(cat "$RUNDIR/nfqws2.pid" 2>/dev/null)" 2>/dev/null; then
        log "nfqws2 calisiyor (qnum $QNUM, tcpseg stratejisi)"
        return 0
    fi
    log "HATA: nfqws2 baslatilamadi ($LOGDIR/nfqws2.log)"
    return 1
}

# ---------- DNS yonlendirme ----------
add_dns_rules()
{
    iptables -t nat -I PREROUTING 1 -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT
    iptables -t nat -I PREROUTING 1 -p tcp --dport 53 -j REDIRECT --to-ports $DNS_PORT
    iptables -t nat -I OUTPUT 1 -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT
    iptables -t nat -I OUTPUT 1 -p tcp --dport 53 -j REDIRECT --to-ports $DNS_PORT
    log "DNS yonlendirme kurallari eklendi"
}

# ---------- DPI kurallari (POSTROUTING: yerel + hotspot) ----------
add_dpi_rules()
{
    iptables -t mangle -N DPI_TR_TCP 2>/dev/null

    iptables -t mangle -A DPI_TR_TCP -d 127.0.0.0/8 -j RETURN
    iptables -t mangle -A DPI_TR_TCP -d 10.0.0.0/8 -j RETURN
    iptables -t mangle -A DPI_TR_TCP -d 172.16.0.0/12 -j RETURN
    iptables -t mangle -A DPI_TR_TCP -d 192.168.0.0/16 -j RETURN
    iptables -t mangle -A DPI_TR_TCP -d 100.64.0.0/10 -j RETURN

    CB=""
    if iptables -m connbytes --help >/dev/null 2>&1; then
        CB="-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:9"
    fi

    if ! iptables -t mangle -A DPI_TR_TCP -m mark ! --mark $MARK -p tcp -m multiport --dports $TCP_PORTS $CB -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null; then
        CB=""
        log "UYARI: connbytes kullanilamadi, TCP limitsiz"
        iptables -t mangle -A DPI_TR_TCP -m mark ! --mark $MARK -p tcp -m multiport --dports $TCP_PORTS -j NFQUEUE --queue-num $QNUM --queue-bypass
    fi

    iptables -t mangle -A POSTROUTING -j DPI_TR_TCP
    log "DPI kurallari eklendi (NFQUEUE $QNUM)"
}

# ---------- acilis ----------
main()
{
    while [ "$(/system/bin/getprop sys.boot_completed)" != "1" ]; do
        sleep 2
    done
    sleep 5

    rm -f "$RUNDIR/stop"
    chmod 755 "$NFQWS2" "$DNSPROXY" 2>/dev/null

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
    fi

    if start_nfqws2; then
        add_dpi_rules
    fi

    log "baslatma tamamlandi"
}

# ---------- bekci ----------
check_dpi()
{
    [ -x "$NFQWS2" ] || return
    if ! kill -0 "$(cat "$RUNDIR/nfqws2.pid" 2>/dev/null)" 2>/dev/null; then
        log "nfqws2 durmus, yeniden baslatiliyor"
        start_nfqws2
    fi
}

check_dns()
{
    [ -x "$DNSPROXY" ] || return
    if ! kill -0 "$(cat "$RUNDIR/dnsproxy.pid" 2>/dev/null)" 2>/dev/null; then
        log "dnsproxy durmus, yeniden baslatiliyor"
        if ! start_dns; then
            log "dnsproxy tekrar baslamadi, DNS yonlendirme kaldiriliyor"
            cleanup_dns_rules
        fi
    fi
}

watchdog()
{
    while true; do
        if [ -f "$RUNDIR/stop" ]; then
            log "stop bayragi goruldu, watchdog cikiyor"
            exit 0
        fi
        sleep 30
        check_dpi
        check_dns
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
