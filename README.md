# Email-Blacklist-Checker-Slack
IP-based DNSBL (blacklist) checker which reports to slack channel

Simple edit the configuration variables with your IP ranges in CIDR format, and the URL to your slack webhook, and run this app on a daily cron. This will check all of your mailing IP addresses against the most popular DNBL blacklists and report to slack the status each day.
