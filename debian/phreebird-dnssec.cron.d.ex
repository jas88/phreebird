#
# Regular cron jobs for the phreebird-dnssec package
#
0 4	* * *	root	[ -x /usr/bin/phreebird-dnssec_maintenance ] && /usr/bin/phreebird-dnssec_maintenance
