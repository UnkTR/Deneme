#!/system/bin/sh
# discord_dpi uninstall - v8
# Calisan surecleri durdurur, tum DPI/DNS kurallarini siler.
# DPI Panel "Durdur" ve "Yeniden baslat" icin bunu kullanir.
# Elle calistirma: su -c "sh /data/adb/modules/discord_dpi/uninstall.sh"
# v8: bekci (service.sh bg) isim ile de oldurulur (pid dosyasi eskimis olsa da),
#     DPI_TR_IN (gelen paket zinciri) temizlenir.
# (Ogrenilen listeler /data/local/tmp/discord_dpi_lists altinda kalir.)

PATH=/system/bin:/system/xbin:$PATH

MODDIR=${0%/*}
RUNDIR="$MODDIR/run"
DNS_PORT=5335
MARK="0x40000000/0x40000000"
WAN_IFACES="rmnet_data+ rmnet+ ccmni+"

mkdir -p "$RUNDIR"
touch "$RUNDIR/stop" 2>/dev/null

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

if [ -f "$RUNDIR/service.pid" ]; then
    kill_if_ours "$(cat "$RUNDIR/service.pid" 2>/dev/null)" "service.sh" "$RUNDIR/service.pid"
fi
if [ -f "$RUNDIR/nfqws2.pid" ]; then
    kill_if_ours "$(cat "$RUNDIR/nfqws2.pid" 2>/dev/null)" "nfqws2" "$RUNDIR/nfqws2.pid"
fi
if [ -f "$RUNDIR/nfqws.pid" ]; then
    kill_if_ours "$(cat "$RUNDIR/nfqws.pid" 2>/dev/null)" "nfqws" "$RUNDIR/nfqws.pid"
fi
if [ -f "$RUNDIR/dnsproxy.pid" ]; then
    kill_if_ours "$(cat "$RUNDIR/dnsproxy.pid" 2>/dev/null)" "dnsproxy" "$RUNDIR/dnsproxy.pid"
fi

# pid dosyasi eskimis/ezilmis olsa da: bekciyi ve surecleri isimle durdur
pkill -f "service.sh bg" 2>/dev/null
pkill -x nfqws2 2>/dev/null
pkill -x dnsproxy 2>/dev/null

sleep 1

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

while iptables -t mangle -D POSTROUTING -j DPI_TR_TCP 2>/dev/null; do :; done
while iptables -t mangle -D POSTROUTING -j DPI_TR_UDP 2>/dev/null; do :; done
iptables -t mangle -F DPI_TR_TCP 2>/dev/null
iptables -t mangle -F DPI_TR_UDP 2>/dev/null
iptables -t mangle -X DPI_TR_TCP 2>/dev/null
iptables -t mangle -X DPI_TR_UDP 2>/dev/null

# gelen paket zinciri (v12+)
while iptables -t mangle -D PREROUTING -j DPI_TR_IN 2>/dev/null; do :; done
iptables -t mangle -F DPI_TR_IN 2>/dev/null
iptables -t mangle -X DPI_TR_IN 2>/dev/null

# eski surum (v13 denemesi) zinciri
while iptables -t mangle -D PREROUTING -j DPI_RX_TCP 2>/dev/null; do :; done
iptables -t mangle -F DPI_RX_TCP 2>/dev/null
iptables -t mangle -X DPI_RX_TCP 2>/dev/null

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

rm -f "$RUNDIR/stop" "$RUNDIR/service.pid"
exit 0
