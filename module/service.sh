#!/system/bin/sh
# ============================================================
#  discord_dpi - Magisk service.sh (v14)
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
#
#  v12 (HOSTLIST + AUTOHOSTLIST):
#  - DPI desync SADECE lists/user-hosts.txt + otomatik tespit edilen
#    (autohostlist) sitelere uygulanir. Diger siteler (Google, YouTube,
#    speedtest vb.) dokunulmadan gecer -> hiz/gecikme duser degil artar.
#  - Giden (POSTROUTING) + gelen (PREROUTING, DPI_TR_IN: ilk 6 reply
#    paketi ve RST) paketler NFQUEUE 200'e girer; nfqws2 hem RST/redirect
#    hem retransmission ile engeli tespit eder.
#  - QUIC (UDP 443) ayni listelere baglandi. Discord ses (l7=discord) ve
#    STUN (l7=stun) hostlist'ten BAGIMSIZ, her zaman aktif.
#  - nfqws2 --uid=1:3003 ile /data/adb'ye yazamaz: canli listeler
#    /data/local/tmp/discord_dpi_lists altinda (777/666), autohostlist
#    periyodik olarak $MODDIR/lists/autohostlist.txt'e yedeklenir.
#
#  v13 (YANLIS POZITIF DUZELTMESI):
#  - QUIC profilinde --hostlist-auto YOK: gelen UDP kuyruga alinmadigi
#    icin QUIC akislari "cevapsiz = engelli" sanilip listeye ekleniyordu.
#    QUIC profili listeleri sadece OKUR; otomatik tespit yalnizca TCP.
#
#  v14 (EXCLUDE LISTESI):
#  - Teshis: TCP otomatik tespiti de google, googleapis, claude.ai,
#    github, reklam/telemetri alan adlarini yanlislikla autohostlist'e
#    ekliyordu (normal sunucu RST/kapanislari engel sanildi).
#  - Cozum: --hostlist-exclude. Yerlesik exclude listesi hem TCP hem
#    QUIC profilinde aktif; bu alan adlari asla desync almaz ve
#    autohostlist'e eklenmez. Acilista autohostlist'teki eski yanlis
#    kayitlar da temizlenir. Ek alan adi icin lists/exclude-hosts.txt
#    olusturulabilir (opsiyonel).
#  v14.1:
#  - Yerlesik exclude listesi genisletildi (Google/Apple/Microsoft,
#    GitHub, sosyal medya, reklam/telemetri, oyun, TR banka/devlet...).
#    Turkiye'de engelli/kisitli servisler (X, Instagram, Discord, Telegram,
#    Wikipedia...) BILEREK disarida: exclude edilirse bypass almazlar.
#  - Kalici kullanici listesi: lists/exclude-user.txt (/data/local/tmp altinda,
#    yeniden baslatmada silinmez). Sonra: sh service.sh refresh
#  - autohostlist temizligi tek geciste yapilir, dosya izni/sahipligi bozulmaz.
#  - Yeni komutlar: "service.sh refresh" (listeleri yenile, nfqws2 otomatik
#    yeniden okur), "service.sh list" (ogrenilen siteleri goster).
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

# hostlist dosyalari (canli kopya: uid 1 erisebilsin diye /data/local/tmp)
MODLISTS="$MODDIR/lists"
LISTS=/data/local/tmp/discord_dpi_lists
UH="$LISTS/user-hosts.txt"
AH="$LISTS/autohostlist.txt"
DBG="$LISTS/autohostlist.debug.log"
EH="$LISTS/exclude-hosts.txt"
EU="$LISTS/exclude-user.txt"

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
    sync_autolist
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

    while iptables -t mangle -D PREROUTING -j DPI_TR_IN 2>/dev/null; do :; done
    iptables -t mangle -F DPI_TR_IN 2>/dev/null
    iptables -t mangle -X DPI_TR_IN 2>/dev/null

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

# ---------- hostlist dosyalari ----------
setup_lists()
{
    mkdir -p "$LISTS" "$MODLISTS" 2>/dev/null
    chmod 777 "$LISTS" "$MODLISTS" 2>/dev/null

    # sabit liste her acilista modulden yenilenir (duzenlemeler gecerli olsun)
    if [ -f "$MODLISTS/user-hosts.txt" ]; then
        cp -f "$MODLISTS/user-hosts.txt" "$UH" 2>/dev/null
    fi
    [ -f "$UH" ] || : > "$UH"

    # autohostlist KALICI: varsa dokunulmaz, yoksa modul kopyasindan/bos olusur
    if [ ! -f "$AH" ]; then
        if [ -f "$MODLISTS/autohostlist.txt" ]; then
            cp -f "$MODLISTS/autohostlist.txt" "$AH" 2>/dev/null
        else
            : > "$AH"
        fi
    fi
    [ -f "$MODLISTS/autohostlist.txt" ] || cp -f "$AH" "$MODLISTS/autohostlist.txt" 2>/dev/null
    [ -f "$DBG" ] || : > "$DBG"

    chmod 644 "$UH" 2>/dev/null
    chmod 666 "$AH" "$DBG" "$MODLISTS/autohostlist.txt" 2>/dev/null

    # exclude listesi: yerlesik + modul dosyasi + kalici kullanici dosyasi
    # (gecici dosyada hazirlanip tek hamlede yerine konur)
    [ -f "$EU" ] || : > "$EU"
    chmod 666 "$EU" 2>/dev/null
    _tmp="$LISTS/.exclude.new"
    cat > "$_tmp" <<'EXEOF'
# ---- Google / Android / YouTube ----
google.com
google.com.tr
googleapis.com
gstatic.com
googleusercontent.com
googlevideo.com
ggpht.com
gvt1.com
gvt2.com
gvt3.com
1e100.net
googlesyndication.com
googleadservices.com
googletagmanager.com
googletagservices.com
google-analytics.com
doubleclick.net
admob.com
app-measurement.com
crashlytics.com
android.com
gmail.com
goo.gl
g.co
youtube.com
youtu.be
ytimg.com
youtube-nocookie.com
youtubekids.com
recaptcha.net
googlezip.net
gcr.io
ampproject.org
waze.com
fitbit.com
chromium.org
withgoogle.com
# ---- Apple ----
apple.com
apple.com.tr
icloud.com
icloud-content.com
mzstatic.com
cdn-apple.com
aaplimg.com
apple-dns.net
apple.news
apple-cloudkit.com
itunes.com
me.com
mac.com
apple.co
# ---- Microsoft ----
microsoft.com
microsoftonline.com
microsoftstore.com
live.com
office.com
office.net
office365.com
outlook.com
hotmail.com
sharepoint.com
onedrive.com
skype.com
windows.com
windowsupdate.com
msftconnecttest.com
msedge.net
msauth.net
msftauth.net
msecnd.net
azure.com
bing.com
msn.com
xbox.com
xboxlive.com
visualstudio.com
vsassets.io
vscode-cdn.net
clarity.ms
# ---- GitHub / gelistirici altyapisi ----
github.com
githubassets.com
githubusercontent.com
githubapp.com
githubcopilot.com
ghcr.io
github.dev
github.blog
npmjs.com
npmjs.org
nodejs.org
python.org
pypi.org
pythonhosted.org
rust-lang.org
crates.io
golang.org
go.dev
docker.com
docker.io
gitlab.com
bitbucket.org
stackoverflow.com
stackexchange.com
sstatic.net
jetbrains.com
gradle.org
maven.org
flutter.dev
dart.dev
cocoapods.org
brew.sh
termux.dev
termux.com
mozilla.org
mozilla.net
mozilla.com
firefox.com
jsdelivr.net
jsdelivr.com
unpkg.com
# ---- Cloudflare ----
cloudflare.com
cloudflare-dns.com
cloudflareinsights.com
# ---- Yapay zeka ----
openai.com
chatgpt.com
oaistatic.com
oaiusercontent.com
anthropic.com
claude.ai
claude.com
perplexity.ai
huggingface.co
# ---- Cihaz ureticileri (Xiaomi / Samsung) ----
xiaomi.com
mi.com
miui.com
xiaomi.net
mi-img.com
samsung.com
samsungapps.com
samsungcloud.com
samsungdm.com
samsungknox.com
samsungosp.com
samsungconsent.com
smartthings.com
galaxyappstore.com
# ---- Sosyal medya / yayin / is araclari (Turkiye'de rutin engeli olmayanlar) ----
facebook.com
facebook.net
fb.com
fbcdn.net
fbsbx.com
fb.me
fb.watch
messenger.com
meta.com
facebookmail.com
whatsapp.com
whatsapp.net
wa.me
tiktok.com
tiktokv.com
tiktokcdn.com
tiktokcdn-us.com
tiktokcdn-eu.com
ttwstatic.com
byteoversea.com
ibytedtos.com
ibyteimg.com
musical.ly
muscdn.com
bytedapm.com
bytedance.com
snapchat.com
snap.com
sc-cdn.net
snapkit.co
pinterest.com
pinimg.com
pin.it
linkedin.com
licdn.com
lnkd.in
twitch.tv
ttvnw.net
jtvnw.net
twitchcdn.net
twitchsvc.net
spotify.com
scdn.co
spotifycdn.com
spoti.fi
netflix.com
nflxvideo.net
nflximg.net
nflximg.com
nflxso.net
nflxext.com
fast.com
disneyplus.com
disney-plus.net
dssott.com
bamgrid.com
primevideo.com
amazon.com
amazon.com.tr
media-amazon.com
ssl-images-amazon.com
audible.com
imdb.com
zoom.us
zoom.com
slack.com
slack-edge.com
dropbox.com
dropboxstatic.com
dropboxapi.com
notion.so
figma.com
canva.com
adobe.com
adobe.io
adobelogin.com
typekit.net
paypal.com
paypalobjects.com
stripe.com
# ---- Reklam / analitik / telemetri ----
liftoff-creatives.io
tiqcdn.com
amazon-adsystem.com
applovin.com
applvn.com
unity3d.com
ironsrc.com
supersonicads.com
mopub.com
vungle.com
adcolony.com
inmobi.com
chartboost.com
fyber.com
adjust.com
adjust.io
appsflyer.com
appsflyersdk.com
branch.io
singular.net
amplitude.com
mixpanel.com
segment.io
segment.com
sentry.io
bugsnag.com
newrelic.com
nr-data.net
datadoghq.com
onesignal.com
braze.com
criteo.com
criteo.net
taboola.com
outbrain.com
adnxs.com
rubiconproject.com
pubmatic.com
openx.net
casalemedia.com
adsrvr.org
scorecardresearch.com
quantserve.com
hotjar.com
hotjar.io
demdex.net
omtrdc.net
everesttech.net
moatads.com
doubleverify.com
smartadserver.com
adform.net
bidswitch.net
3lift.com
tapad.com
smaato.net
crwdcntrl.net
krxd.net
bluekai.com
# ---- Oyun / konsol ----
steampowered.com
steamcommunity.com
steamcontent.com
steamstatic.com
steamserver.net
steamusercontent.com
steam-chat.com
steamgames.com
valvesoftware.com
valve.net
epicgames.com
unrealengine.com
playstation.com
playstation.net
sonyentertainmentnetwork.com
nintendo.com
nintendo.net
ea.com
battle.net
blizzard.com
ubisoft.com
ubi.com
riotgames.com
rockstargames.com
supercell.com
supercellid.com
mojang.com
minecraft.net
# ---- Turkiye: devlet / operator / banka / alisveris ----
gov.tr
edu.tr
turkcell.com.tr
vodafone.com.tr
turktelekom.com.tr
superonline.net
isbank.com.tr
garantibbva.com.tr
ziraatbank.com.tr
akbank.com
yapikredi.com.tr
halkbank.com.tr
vakifbank.com.tr
qnbfinansbank.com
denizbank.com
enpara.com
papara.com
ing.com.tr
teb.com.tr
kuveytturk.com.tr
trendyol.com
hepsiburada.com
n11.com
sahibinden.com
yemeksepeti.com
getir.com
migros.com.tr
a101.com.tr
sok.com.tr
carrefoursa.com
mediamarkt.com.tr
teknosa.com
vatanbilgisayar.com
monsternotebook.com.tr
turkishairlines.com
thy.com
flypgs.com
# ---- BILEREK DISARIDA (Turkiye'de engellenen/kisitlanan servisler) ----
# Bunlari dislarsan bypass onlara hic uygulanmaz. Yanlis pozitif cok olursa
# ilgili satirdaki # isaretini kaldir (sonra: service.sh refresh).
# instagram.com
# cdninstagram.com
# threads.net
# twitter.com
# x.com
# twimg.com
# t.co
# telegram.org
# t.me
# reddit.com
# redd.it
# redditmedia.com
# redditstatic.com
# wikipedia.org
# wikimedia.org
# blogspot.com
# signal.org
# bsky.app
EXEOF
    [ -f "$MODLISTS/exclude-hosts.txt" ] && cat "$MODLISTS/exclude-hosts.txt" >> "$_tmp" 2>/dev/null
    cat "$EU" >> "$_tmp" 2>/dev/null
    # CRLF / bosluk temizligi
    tr -d '\r' < "$_tmp" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' > "$EH" 2>/dev/null
    rm -f "$_tmp"
    chmod 644 "$EH" 2>/dev/null

    # autohostlist'teki yanlis pozitifleri TEK geciste temizle.
    # sed -i / mv KULLANMA: dosya sahibi/izni degisirse nfqws2 (uid 1) yazamaz.
    _pat="$LISTS/.exclude.pat"
    _out="$LISTS/.auto.clean"
    grep -v -e '^#' -e '^$' "$EH" 2>/dev/null \
        | sed -e 's/\./\\./g' -e 's/.*/(^|\\.)&$/' > "$_pat"
    if [ -s "$_pat" ] && [ -s "$AH" ]; then
        grep -v -E -f "$_pat" "$AH" > "$_out" 2>/dev/null
        # rc 0/1 = tamam (1: hepsi silindi); 2 = hata -> dokunma
        if [ $? -le 1 ]; then
            cat "$_out" > "$AH" 2>/dev/null
        fi
    fi
    rm -f "$_pat" "$_out"
    chmod 666 "$AH" "$MODLISTS/autohostlist.txt" 2>/dev/null
}

sync_autolist()
{
    [ -f "$AH" ] || return 0
    cmp -s "$AH" "$MODLISTS/autohostlist.txt" 2>/dev/null && return 0
    cp -f "$AH" "$MODLISTS/autohostlist.txt" 2>/dev/null
    chmod 666 "$MODLISTS/autohostlist.txt" 2>/dev/null
}

# ---------- nfqws2 (zapret2) ----------
# Otomatik tespit ayari: yanlis pozitif cok olursa AUTO_FAILS'i 4-5 yap
AUTO_FAILS=3
AUTO_TIME=60
AUTO_RETRANS=3
# $1 = seviye: 0 tam | 1 fail-threshold/time parametresiz | 2 sadece TCP
build_nfqws2_args()
{
    _lvl="$1"
    _a="--qnum=$QNUM --daemon --pidfile=$RUNDIR/nfqws2.pid"
    _a="$_a --uid=1:3003 --bind-fix4 --bind-fix6 --fwmark=0x40000000"
    _a="$_a --debug=@$LOGDIR/nfqws2.log"
    _a="$_a --lua-init=@$LUATMP/zapret-lib.lua"
    _a="$_a --lua-init=@$LUATMP/zapret-antidpi.lua"

    _haveq=0
    if [ "$_lvl" -lt 2 ] && [ -s "$LUATMP/quic_initial.bin" ]; then
        _haveq=1
        _a="$_a --blob=quic_initial:@$LUATMP/quic_initial.bin"
    fi

    _hl="--hostlist=$UH --hostlist-auto=$AH --hostlist-exclude=$EH"
    _auto="--hostlist-auto-retrans-threshold=$AUTO_RETRANS --hostlist-auto-debug=$DBG"
    if [ "$_lvl" -eq 0 ]; then
        _auto="$_auto --hostlist-auto-fail-threshold=$AUTO_FAILS --hostlist-auto-fail-time=$AUTO_TIME"
    fi

    # Profil 1: TCP 80/443 - sadece listedeki / otomatik tespit edilen siteler
    _a="$_a --filter-tcp=$TCP_PORTS $_hl $_auto"
    _a="$_a --payload=tls_client_hello"
    _a="$_a --lua-desync=tcpseg:pos=0,1:ip_id=rnd:repeats=1"

    if [ "$_lvl" -lt 2 ]; then
        # Profil 2: QUIC (UDP 443) - listeleri SADECE okur (hostlist-auto YOK:
        # gelen UDP kuyruga alinmadigi icin yanlis pozitif uretiyordu)
        if [ $_haveq -eq 1 ]; then
            _a="$_a --new --filter-udp=443 --filter-l7=quic"
            _a="$_a --hostlist=$UH --hostlist=$AH --hostlist-exclude=$EH"
            _a="$_a --payload=quic_initial"
            _a="$_a --lua-desync=fake:blob=quic_initial:repeats=6"
        fi
        # Profil 3: Discord ses + STUN - hostlist'ten BAGIMSIZ, hep aktif
        _a="$_a --new --filter-udp=1-65535 --filter-l7=discord,stun"
        _a="$_a --payload=stun,discord_ip_discovery"
        _a="$_a --lua-desync=fake:blob=0x00000000000000000000000000000000:ip_ttl=4:ip6_ttl=4:repeats=6"
    fi
    echo "$_a"
}

start_nfqws2()
{
    [ -x "$NFQWS2" ] || { log "HATA: nfqws2 bulunamadi"; return 1; }
    [ -f "$LUADIR/zapret-lib.lua" ] || { log "HATA: modul lua dosyalari eksik"; return 1; }

    # KRITIK: nfqws2 --uid ile yetki dusurunce /data/adb'yi okuyamaz
    # (root-only). Lua dosyalarini UID 1'in erisebilecegi yere kopyala.
    rm -rf "$LUATMP" 2>/dev/null
    mkdir -p "$LUATMP" 2>/dev/null
    cp -f "$LUADIR"/*.lua "$LUATMP"/ 2>/dev/null
    if [ -s "$MODDIR/blobs/quic_initial.bin" ]; then
        cp -f "$MODDIR/blobs/quic_initial.bin" "$LUATMP/quic_initial.bin" 2>/dev/null
    else
        log "UYARI: blobs/quic_initial.bin yok, QUIC profili devre disi"
    fi
    if [ ! -f "$LUATMP/zapret-lib.lua" ] || [ ! -f "$LUATMP/zapret-antidpi.lua" ]; then
        log "HATA: lua dosyalari $LUATMP altina kopyalanamadi"
        return 1
    fi
    chmod 755 "$LUATMP" 2>/dev/null
    chmod 644 "$LUATMP"/*.lua "$LUATMP"/*.bin 2>/dev/null

    setup_lists
    echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null

    for _lvl in 0 1 2; do
        : > "$LOGDIR/nfqws2.log"
        chmod 666 "$LOGDIR/nfqws2.log" 2>/dev/null
        : > "$RUNDIR/nfqws2.pid"
        chmod 666 "$RUNDIR/nfqws2.pid" 2>/dev/null

        _args="$(build_nfqws2_args $_lvl)"
        "$NFQWS2" $_args >> "$LOGDIR/nfqws2.log" 2>&1
        sleep 2
        _pid="$(cat "$RUNDIR/nfqws2.pid" 2>/dev/null)"
        if pid_alive "$_pid" "nfqws2"; then
            log "nfqws2 calisiyor (qnum $QNUM, hostlist+autohostlist+exclude, seviye $_lvl, uid=1:3003, pid $_pid)"
            return 0
        fi
        log "UYARI: nfqws2 seviye $_lvl baslamadi: $(tail -n 3 "$LOGDIR/nfqws2.log" 2>/dev/null | tr '\n' '|' | cut -c1-300)"
    done

    if grep -q "not accessible" "$LOGDIR/nfqws2.log" 2>/dev/null; then
        log "HATA: nfqws2 lua dosyalarina erisemiyor (izin sorunu)"
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

# ---------- DPI kurallari (mangle POSTROUTING: yerel + hotspot) ----------
# Giden : DPI_TR_TCP (80/443) + DPI_TR_UDP (QUIC 443, Discord ses, STUN)
# Gelen : DPI_TR_IN  (PREROUTING; sunucudan donen ilk paketler + RST)
#         -> nfqws2 autohostlist engel tespiti (RST / redirect / retrans)
add_dpi_rules()
{
    LAN_NETS="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10"

    iptables -t mangle -N DPI_TR_TCP 2>/dev/null
    iptables -t mangle -N DPI_TR_UDP 2>/dev/null
    iptables -t mangle -N DPI_TR_IN 2>/dev/null

    for n in $LAN_NETS; do
        iptables -t mangle -A DPI_TR_TCP -d $n -j RETURN
        iptables -t mangle -A DPI_TR_UDP -d $n -j RETURN
        iptables -t mangle -A DPI_TR_IN -s $n -j RETURN
    done

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

    # UDP: QUIC (443) + Discord ses / STUN portlari
    iptables -t mangle -A DPI_TR_UDP -m mark ! --mark $MARK $OC -p udp --dport 443 $CB -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null
    iptables -t mangle -A DPI_TR_UDP -m mark ! --mark $MARK $OC -p udp -m multiport --dports 3478:3481,19294:19344,50000:65535 $CB -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null

    # Gelen: RST her zaman, SYN/ACK + ServerHello/redirect icin ilk 6 reply paketi
    iptables -t mangle -A DPI_TR_IN -p tcp -m multiport --sports $TCP_PORTS --tcp-flags RST RST -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null
    if [ -n "$CB" ]; then
        iptables -t mangle -A DPI_TR_IN -p tcp -m multiport --sports $TCP_PORTS -m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes 1:6 -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null
    else
        log "UYARI: connbytes yok, gelen paket kancasi sadece RST ile sinirli"
    fi

    iptables -t mangle -A POSTROUTING -j DPI_TR_TCP
    iptables -t mangle -A POSTROUTING -j DPI_TR_UDP
    iptables -t mangle -I PREROUTING 1 -j DPI_TR_IN
    log "DPI kurallari POSTROUTING + PREROUTING'e baglandi"
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
    if ! iptables -t mangle -C POSTROUTING -j DPI_TR_TCP 2>/dev/null \
        || ! iptables -t mangle -C POSTROUTING -j DPI_TR_UDP 2>/dev/null \
        || ! iptables -t mangle -C PREROUTING -j DPI_TR_IN 2>/dev/null; then
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
    sync_autolist
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
    refresh)
        # listeleri yeniden olustur (nfqws2 dosya degisimini kendi izler)
        setup_lists
        sync_autolist
        echo "exclude: $(grep -c -v -e '^#' -e '^$' "$EH") alan adi | ogrenilen: $(grep -c -v -e '^#' -e '^$' "$AH")"
        ;;
    list)
        cat "$AH"
        ;;
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
