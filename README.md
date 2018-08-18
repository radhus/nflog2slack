# nflog2slack

Listens to nflog messages and sends them to Slack - a poor man's IDS!

Usage with nftables:

```
$ nft add rule filter input tcp dport 22 ct state new log prefix "SSH" group 10 accept
$ ./nflog2slack -url https://hooks.slack.com/services/XXX/YYY/ZZZ -groups 10
```