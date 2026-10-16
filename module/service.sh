#!/system/bin/sh
# ============================================================
#  discord_dpi - Magisk service.sh (v11)
#  Motor  : zapret2 / nfqws2 (Android ARM64)
#  Strateji: --payload=tls_client_hello
#            --lua-desync=tcpseg:pos=0,1:ip_id=rnd:repeats=1
#  DNS    : dnsproxy (DoH :5335) + iptables REDIRECT (telefon + hotspot)
#  nfqttl ile UYUMLU: onun zincirlerine/kuyruguna dokunulmaz.
#
#  v11 (DNS DUZELTMESI):
#  - Teshis: REDIRECT zinciri calisiyor (netd ve nslookup sorgulari
#    127.0.0.1:5335'ten cevap aliyor) ama dnsproxy'nin tum DoH
#    upstream'leri aninda basarisiz oluyordu (SERVFAIL).
#  - Olasi neden: Go/dnsproxy Android'de kok sertifikalari bulamiyor.
#  - Cozum: sirayla 3 CA kaynagi denenir (modul ici Mozilla paketi,
#    APEX conscrypt dizini, sistem dizini). Her aday icin gercek DNS
#    sorgusu (REDIRECT yolundan) yapilir, calisan secilir.
#  - Basarisizlikta dnsproxy.log'un son satirlari service.log'a dokulur.
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

# dnsproxy icin CA adaylari (sirayla denenir)
CA_CANDS="file:$MODDIR/cacert.pem dir:/apex/com.android.conscrypt/cacerts dir:/system/etc/security/cacerts"

mkdir -p "$RUNDIR" "$LOGDIR"
DNSOFF=0
DPIOFF=0

# ping -W destegi var mi? (yoksa timeout'a guvenilir)
PING_W=""
if ! ping -W 1 -c 1 127.0.0.1 2>&1 | grep -qi "unknown"; then
    PING_W="-W 2"
fi

log()
{
    echo "$(date +%Y-%m-%d_%H:%M:%S) $*" >> "$LOGF"
}

have()
{
    command -v "$1" >/dev/null 2>&1
}

find_busybox()
{
    for b in busybox /data/adb/magisk/busybox /data/adb/ksu/bin/busybox; do
        if command -v "$b" >/dev/null 2>&1; then echo "$b"; return 0; fi
    done
    return 1
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
    sleep 1
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
# $1 = "file:<yol>" | "dir:<yol>" | "" (varsayilan)
start_dns()
{
    [ -x "$DNSPROXY" ] || { log "HATA: dnsproxy bulunamadi"; return 1; }
    _ca="$1"

    echo "=== dnsproxy baslatiliyor (CA: ${_ca:-varsayilan}) ===" >> "$LOGDIR/dnsproxy.log"

    case "$_ca" in
        file:*)
            export SSL_CERT_FILE="${_ca#file:}"
            export SSL_CERT_DIR=/dev/null
            ;;
        dir:*)
            export SSL_CERT_DIR="${_ca#dir:}"
            export SSL_CERT_FILE=/dev/null
            ;;
    esac

    # IP-literal DoH, parallel mod: biri blokluysa digerleri cevap verir.
    # NOT: 94.140.14.14 TR'de erisilemiyor (curl 000) -> listede yok.
    "$DNSPROXY" -v -l 0.0.0.0 -p $DNS_PORT \
        -u https://8.8.8.8/dns-query \
        -u https://1.0.0.1/dns-query \
        -u https://94.140.15.15/dns-query \
        -u https://9.9.9.9/dns-query \
        --cache --cache-size=4194304 --upstream-mode=parallel --timeout=3s \
        >> "$LOGDIR/dnsproxy.log" 2>&1 &
    echo $! > "$RUNDIR/dnsproxy.pid"

    unset SSL_CERT_FILE SSL_CERT_DIR

    sleep 2
    if pid_alive "$(cat "$RUNDIR/dnsproxy.pid" 2>/dev/null)" "dnsproxy"; then
        log "dnsproxy calisiyor (port $DNS_PORT, CA: ${_ca:-varsayilan})"
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

    # root (uid 0) trafigi kuyruklanmaz -> dnsproxy DoH'u desync'ten muaf.
    OC="-m owner ! --uid-owner 0"

    if iptables -t mangle -A DPI_TR_TCP -m mark ! --mark $MARK $OC -p tcp -m multiport --dports $TCP_PORTS $CB -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null; then
        log "DPI kurali eklendi (NFQUEUE $QNUM, root haric, connbytes)"
    elif iptables -t mangle -A DPI_TR_TCP -m mark ! --mark $MARK $OC -p tcp -m multiport --dports $TCP_PORTS -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null; then
        CB=""
        log "DPI kurali eklendi (NFQUEUE $QNUM, root haric; connbytes yok)"
    else
        OC=""
        CB=""
        log "UYARI: owner eslesmesi kullanilamadi, root trafigi de kuyruklanir"
        iptables -t mangle -A DPI_TR_TCP -m mark ! --mark $MARK -p tcp -m multiport --dports $TCP_PORTS -j NFQUEUE --queue-num $QNUM --queue-bypass
    fi

    iptables -t mangle -A POSTROUTING -j DPI_TR_TCP
    log "DPI kurallari POSTROUTING'e baglandi"
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

# DNS yonlendirme yolunu dogrudan test eder (netd'e GIRMEZ):
# busybox nslookup 8.8.8.8:53 -> iptables REDIRECT -> 127.0.0.1:5335
# Donus: 0 = en az bir host cozuldu, 1 = hicbiri cozulmedi
dns_probe()
{
    BB="$(find_busybox)"
    if [ -z "$BB" ]; then log "PROBE atlandi: busybox yok"; return 0; fi
    _ok=1
    for h in example.com discord.com; do
        t0=$(date +%s)
        out=$(timeout 8 "$BB" nslookup "$h" 8.8.8.8 2>&1)
        t1=$(date +%s)
        res="FAIL"
        if echo "$out" | grep -q "Name:"; then
            res="OK"
            _ok=0
        fi
        log "PROBE[$h] $res $((t1-t0))s: $(echo "$out" | tr '\n' '|' | cut -c1-350)"
    done
    return $_ok
}

# Her CA adayi icin: dnsproxy baslat -> REDIRECT ekle -> gercek sorgu dene.
# Calisan ilk adayda durur (kurallar yerinde kalir). Hicbiri calismazsa 1.
setup_dns_stack()
{
    for c in $CA_CANDS; do
        case "$c" in
            file:*) [ -s "${c#file:}" ] || { log "CA adayi yok, atlandi: $c"; continue; } ;;
            dir:*)  [ -d "${c#dir:}" ]  || { log "CA adayi yok, atlandi: $c"; continue; } ;;
        esac

        cleanup_dns_rules
        kill_dns

        if ! start_dns "$c"; then
            continue
        fi

        add_dns_rules
        sleep 1
        if dns_probe; then
            log "DNS CA SECILDI: $c (DoH calisiyor)"
            return 0
        fi

        log "DNS CA adayi basarisiz: $c"
        log "dnsproxy.log son satirlar:"
        tail -n 12 "$LOGDIR/dnsproxy.log" 2>/dev/null >> "$LOGF"
        cleanup_dns_rules
        kill_dns
    done
    return 1
}

# Gate fail edince sorunu yerinde belgelemek icin
dump_dns_diag()
{
    log "DIAG ---- baslangic ----"
    getprop 2>/dev/null | grep -i dns | head -n 15 >> "$LOGF"
    log "DIAG dnsproxy.log (son 30 satir):"
    tail -n 30 "$LOGDIR/dnsproxy.log" 2>/dev/null >> "$LOGF"
    log "DIAG nat OUTPUT:"
    iptables -t nat -L OUTPUT -v -n 2>/dev/null >> "$LOGF"
    log "DIAG nat PREROUTING:"
    iptables -t nat -L PREROUTING -v -n 2>/dev/null >> "$LOGF"
    log "DIAG dinleyiciler:"
    netstat -ulpn 2>/dev/null | grep 5335 >> "$LOGF"
    log "DIAG CA dizinleri:"
    ls -d /apex/com.android.conscrypt/cacerts /system/etc/security/cacerts "$MODDIR/cacert.pem" 2>&1 >> "$LOGF"
    log "DIAG ---- son ----"
}

# Google KULLANILMAZ: onbellekten cozulebilir ve testi yaniltir.
dns_gate()
{
    _logged=0
    i=0
    while [ $i -lt 3 ]; do
        for h in example.com www.bing.com wikipedia.org; do
            out=$(timeout 6 ping $PING_W -c 1 $h 2>&1)
            if echo "$out" | grep -Eq '\([0-9]'; then
                return 0
            fi
            if [ $_logged -eq 0 ]; then
                log "DNS_GATE ilk hata [$h]: $(echo "$out" | tr '\n' '|' | cut -c1-300)"
                _logged=1
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

    : > "$LOGDIR/dnsproxy.log"
    if setup_dns_stack; then
        if dns_gate; then
            log "DNS testi BASARILI"
        else
            log "HATA: DNS_GATE (netd yolu) BASARISIZ -> DNS yonlendirme geri alindi (internet korunur)"
            dump_dns_diag
            cleanup_dns_rules
            kill_dns
            DNSOFF=10
        fi
    else
        log "HATA: hicbir CA adayiyla DoH calismadi -> DNS yonlendirme yok (internet korunur)"
        dump_dns_diag
        cleanup_dns_rules
        kill_dns
        DNSOFF=10
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
        if ! setup_dns_stack; then
            log "dnsproxy/DoH tekrar calismadi, DNS yonlendirme kaldiriliyor"
            cleanup_dns_rules
            kill_dns
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
