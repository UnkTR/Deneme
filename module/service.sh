#!/system/bin/sh
# ============================================================
#  discord_dpi - Magisk service.sh (v8)
#  Motor  : zapret2 / nfqws2 (Android ARM64)
#  Strateji (ISS'de test edildi):
#    --payload=tls_client_hello
#    --lua-desync=tcpseg:pos=0,1:ip_id=rnd:repeats=1
#  DNS    : dnsproxy (DoH :5335)
#  nfqttl ile UYUMLU: onun zincirlerine/kuyruguna dokunulmaz.
#  IPv6 mudahalesi YOK. QUIC/UDP'ye dokunulmaz.
#
#  v8 DUZELTMELERI (v7 loglarindan tespit edildi):
#  1) nfqws2, --uid ile yetki dusurunce Lua dosyalarini /data/adb
#     altindan OKUYAMIYORDU ve hemen cikiyordu ("LUA file not
#     accessible"). Lua dosyalari artik /data/local/tmp/discord_dpi_lua
#     altina kopyalanip oradan yukleniyor.
#  2) Bos pid dosyasi yuzunden surec "calisiyor" sanilabiliyordu.
#     Artik pid_alive(): pid dolu + /proc girdisi var + cmdline'da
#     isim geciyor kontrolu yapilir.
#  3) DNS testi Google'a bagimli degildi; Google onbellekten
#     cozulebildigi icin testi yanlis geciriyordu. Test artik
#     example.com gibi Google OLMAYAN adlarla yapilir; basarisizsa
#     DNS yonlendirme kurallari derhal geri alinir.
#  4) dnsproxy upstream: 8.8.8.8, 1.0.0.1, 1.1.1.1, 9.9.9.9
#     (parallel modda; biri blokluyse digeri cevap verir).
# ============================================================

PATH=/system/bin:/system/xbin:$PATH

MODDIR=${0%/*}
BINDIR="$MODDIR/system/bin"
LUADIR="$MODDIR/lua"
LUATMP=/data/local/tmp/discord_dpi_lua
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
DNSOFF=0
DPIOFF=0

log()
{
    echo "$(date +%Y-%m-%d_%H:%M:%S) $*" >> "$LOGF"
}

have()
{
    command -v "$1" >/dev/null 2>&1
}

# pid dolu mu, /proc girdisi var mi, istege bagli isim eslesmesi
pid_alive()
{
    _p="$1"
    [ -n "$_p" ] || return 1
    [ -d "/proc/$_p" ] || return 1
    if [ -n "$2" ]; then
        grep -q "$2" "/proc/$_p/cmdline" 2>/dev/null || return 1
    fi
    return 0
}

kill_if_ours()
{
    _pid="$1"
    _name="$2"
    _file="$3"
    if pid_alive "$_pid" "$_name"; then
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

# ---------- temizlik (eski surumlerin kurallarini da kaldirir) ----------
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
    while iptables -t mangle -D POSTROUTING -j DPI_TR_TCP 2>/dev/null; do :; done
    while iptables -t mangle -D POSTROUTING -j DPI_TR_UDP 2>/dev/null; do :; done
    iptables -t mangle -F DPI_TR_TCP 2>/dev/null
    iptables -t mangle -F DPI_TR_UDP 2>/dev/null
    iptables -t mangle -X DPI_TR_TCP 2>/dev/null
    iptables -t mangle -X DPI_TR_UDP 2>/dev/null

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

# ---------- dnsproxy ----------
start_dns()
{
    [ -x "$DNSPROXY" ] || { log "HATA: dnsproxy bulunamadi"; return 1; }
    : > "$LOGDIR/dnsproxy.log"

    # Upstream'ler IP-literal DoH: TR'de biri blokluysa digerleri
    # cevap verir (parallel mod). Bootstrap kullanilmaz.
    "$DNSPROXY" -l 0.0.0.0 -p $DNS_PORT \
        -u https://8.8.8.8/dns-query \
        -u https://1.0.0.1/dns-query \
        -u https://1.1.1.1/dns-query \
        -u https://9.9.9.9/dns-query \
        --cache --cache-size=4194304 --upstream-mode=parallel --timeout=3s \
        >> "$LOGDIR/dnsproxy.log" 2>&1 &
    echo $! > "$RUNDIR/dnsproxy.pid"
    sleep 2
    if pid_alive "$(cat "$RUNDIR/dnsproxy.pid" 2>/dev/null)" "dnsproxy"; then
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
    [ -f "$LUADIR/zapret-lib.lua" ] || { log "HATA: modul lua dosyalari eksik"; return 1; }

    # KRITIK: nfqws2 --uid ile yetki dusurunce /data/adb'yi okuyamaz
    # (root-only). Lua dosyalarini UID 1'in erisebilecegi yere kopyala.
    rm -rf "$LUATMP" 2>/dev/null
    mkdir -p "$LUATMP" 2>/dev/null
    cp -f "$LUADIR"/*.lua "$LUATMP"/ 2>/dev/null
    if [ ! -f "$LUATMP/zapret-lib.lua" ] || [ ! -f "$LUATMP/zapret-antidpi.lua" ]; then
        log "HATA: lua dosyalari $LUATMP altina kopyalanamadi"
        return 1
    fi
    chmod 755 "$LUATMP" 2>/dev/null
    chmod 644 "$LUATMP"/*.lua 2>/dev/null

    : > "$LOGDIR/nfqws2.log"
    chmod 666 "$LOGDIR/nfqws2.log" 2>/dev/null
    : > "$RUNDIR/nfqws2.pid"
    chmod 666 "$RUNDIR/nfqws2.pid" 2>/dev/null

    "$NFQWS2" --qnum=$QNUM --daemon --pidfile="$RUNDIR/nfqws2.pid" \
        --uid=1:3003 --bind-fix4 --bind-fix6 --fwmark=0x40000000 \
        --debug=@$LOGDIR/nfqws2.log \
        --lua-init=@"$LUATMP/zapret-lib.lua" \
        --lua-init=@"$LUATMP/zapret-antidpi.lua" \
        --payload=tls_client_hello \
        --lua-desync=tcpseg:pos=0,1:ip_id=rnd:repeats=1 \
        >> "$LOGDIR/nfqws2.log" 2>&1
    sleep 2
    _pid="$(cat "$RUNDIR/nfqws2.pid" 2>/dev/null)"
    if pid_alive "$_pid" "nfqws2"; then
        log "nfqws2 calisiyor (qnum $QNUM, tcpseg, uid=1:3003, pid $_pid)"
        return 0
    fi
    if grep -q "not accessible" "$LOGDIR/nfqws2.log" 2>/dev/null; then
        log "HATA: nfqws2 lua dosyalarina erisemiyor (izin sorunu)"
    fi
    log "HATA: nfqws2 baslatilamadi (pid='$_pid', $LOGDIR/nfqws2.log)"
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

# ---------- DPI kurallari (mangle POSTROUTING: yerel + hotspot) ----------
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

# ---------- canli testler (fail-open kapilari) ----------
tcp_gate()
{
    have nc || { log "UYARI: nc yok, TCP testi atlandi"; return 0; }
    i=0
    while [ $i -lt 5 ]; do
        if timeout 5 nc 1.1.1.1 443 < /dev/null > /dev/null 2>&1; then return 0; fi
        if timeout 5 nc 8.8.8.8 443 < /dev/null > /dev/null 2>&1; then return 0; fi
        i=$((i+1))
        sleep 3
    done
    return 1
}

# Google KULLANILMAZ: onbellekten cozulebilir ve testi yaniltir.
dns_gate()
{
    i=0
    while [ $i -lt 3 ]; do
        for h in example.com www.bing.com wikipedia.org; do
            out=$(timeout 6 ping -c 1 $h 2>&1)
            if echo "$out" | grep -Eq '\([0-9]'; then
                return 0
            fi
        done
        i=$((i+1))
        sleep 2
    done
    return 1
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

    if start_nfqws2; then
        add_dpi_rules
        if tcp_gate; then
            log "TCP testi BASARILI"
        else
            log "HATA: TCP testi BASARISIZ -> DPI kurallari geri alindi (internet korunur)"
            cleanup_dpi_rules
            kill_nfqws
            DPIOFF=10
        fi
    fi

    if start_dns; then
        add_dns_rules
        if dns_gate; then
            log "DNS testi BASARILI"
        else
            log "HATA: DNS testi BASARISIZ -> DNS yonlendirme geri alindi (internet korunur)"
            cleanup_dns_rules
            kill_dns
            DNSOFF=10
        fi
    fi

    log "baslatma tamamlandi"
}

# ---------- bekci ----------
check_dpi()
{
    [ -x "$NFQWS2" ] || return
    if ! pid_alive "$(cat "$RUNDIR/nfqws2.pid" 2>/dev/null)" "nfqws2"; then
        log "nfqws2 durmus, yeniden baslatiliyor"
        if ! start_nfqws2; then
            DPIOFF=10
            return
        fi
    fi
    if ! iptables -t mangle -C POSTROUTING -j DPI_TR_TCP 2>/dev/null; then
        log "DPI kurallari eksik, yeniden ekleniyor"
        cleanup_dpi_rules
        add_dpi_rules
        if ! tcp_gate; then
            log "HATA: TCP testi basarisiz -> DPI kurallari kaldirildi"
            cleanup_dpi_rules
            kill_nfqws
            DPIOFF=10
        fi
    fi
}

check_dns()
{
    [ -x "$DNSPROXY" ] || return
    if ! pid_alive "$(cat "$RUNDIR/dnsproxy.pid" 2>/dev/null)" "dnsproxy"; then
        log "dnsproxy durmus, yeniden baslatiliyor"
        if ! start_dns; then
            log "dnsproxy tekrar baslamadi, DNS yonlendirme kaldiriliyor"
            cleanup_dns_rules
            DNSOFF=10
            return
        fi
    fi
    if ! iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT 2>/dev/null; then
        log "DNS kurallari eksik, yeniden ekleniyor"
        cleanup_dns_rules
        add_dns_rules
        if ! dns_gate; then
            log "HATA: DNS testi basarisiz -> yonlendirme kaldirildi"
            cleanup_dns_rules
            kill_dns
            DNSOFF=10
        fi
    fi
}

periodic_health()
{
    if iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT 2>/dev/null; then
        if ! dns_gate; then
            log "PERIYODIK: DNS testi basarisiz -> DNS yonlendirme kaldiriliyor"
            cleanup_dns_rules
            kill_dns
            DNSOFF=10
        fi
    fi
    if iptables -t mangle -C POSTROUTING -j DPI_TR_TCP 2>/dev/null; then
        if ! tcp_gate; then
            log "PERIYODIK: TCP testi basarisiz -> DPI kurallari kaldiriliyor"
            cleanup_dpi_rules
            kill_nfqws
            DPIOFF=10
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
        if [ $DNSOFF -gt 0 ]; then
            DNSOFF=$((DNSOFF-1))
        else
            check_dns
        fi
        if [ $DPIOFF -gt 0 ]; then
            DPIOFF=$((DPIOFF-1))
        else
            check_dpi
        fi
        if [ $((n % 20)) -eq 0 ]; then
            periodic_health
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
