# Show basic crowdsec information in netdata

## Inforation shown:

- Decisions (by Ip, As, Country, Scenario)
- Parser stats (Parsed vs Unparsed lines)
- Buckets (Active, instantiated, poured, expired, overflowed)
- Local API stats (All, machines, bouncers, bouncer decisions)

## Setup

- Copy `crowdsec.chart.py` to `/usr/libexec/netdata/python.d`
- Copy `crowdsec.conf` to `/etc/netdata/python.d`
    - Enable or disable the charts to suit your needs
- Set `crowdsec: yes` in `/etc/netdata/python.d.conf`
- Reload netdata (`sudo systemctl restart netdata`)

## Setup netdata to run without sudo

This is **only needed for decisions**.

### Add netdata to run this command without sudo password

- Add this line to your `/etc/sudoers` file:

`netdata ALL=(root)       NOPASSWD: /path/to/cscli`

> Replace `/path/to/cscli` with the output of `which cscli`

### Disable netdata's sudo protection
```sh
sudo mkdir /etc/systemd/system/netdata.service.d
sudo echo -e '[Service]\nCapabilityBoundingSet=~' | sudo tee /etc/systemd/system/netdata.service.d/unset-capability-bounding-set.conf
sudo systemctl daemon-reload
sudo systemctl restart netdata.service
```