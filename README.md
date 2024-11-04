# hdwake

This tool is for an elegent way to keep your external usb HDD wake all the time, prevent from being on standby (sleeping, spinning-down).

## How to use

Use

```
hdwake list
```
(This command can also query the status of the disk without waking it up, like what `smartctl -i -n standby /dev/sda` `hdparm -C /dev/sdb` do)

you can get a list of all current disks, 

```
     EDILOCA_EN206_512GB_MX_00000000000000000 (/dev/sda): (1) active/idle
                     ELECOM_SSD_0000000000000 (/dev/sdc): (1) active/idle
                 TOSHIBA_MQ01ABD100_000000000 (/dev/sdb): (1) active/idle
```

put the identity string of target HDD like "TOSHIBA_MQ01ABD100_000000000" to /etc/hdwake.conf and everything is ready then.


## Background

If you use external usb drives on Linux, by some chance you will find there is a big delay when reading or writing after a period of inactivity.

This is due to power management, which puts HDD into standby powermode after an idle time.
And switching from standby to active usually costs some time that leads to a delay before any I/O operation.

This is very annoying if you use the USB HDD as a persistent storage.
And some also suggest that frequently spin down and up on HDD may reduce its life.

Normally, one can just use
```
hdparm -B 254 -S 0 /dev/sdx
```
to set APM and standby timeout to prevent this from happenning.

But unfortunately there exist some brands ignore this, and after a mystery time period your HDDs still go standby (sleeping, spinning-down).

There are some dirty hack like using cron or other to touch the HDD after a period, 

* https://unix.stackexchange.com/questions/5211/prevent-a-usb-external-hard-drive-from-sleeping
* https://unix.stackexchange.com/questions/716022/prevent-hd-from-sleeping-in-usb-external-enclosure

but as you don't know what the actual timeout is, it may result in more frequent spinning up and down and finally even harm your HDD.

To solve this, I made (some code borrowed from hdprarm) a daemon called hdwake to automatically take care of everything in this case.
It sets APM and standby timeout at very first stage, and if that's not enough, a built-in checker will automatically detect the timeout and keep the HDD awake all the time.

This daemon also handles /dev/sdx change by using unique identity strings for each disks, so you don't worry about /dev/sdx change after every reboot like the dirty hacks before.

## TODO

- Better documents.
- Add Debian / OpenWRT package build.
- More option for set defaults and limits varibles.
