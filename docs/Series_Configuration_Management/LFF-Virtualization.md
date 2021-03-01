# HomeLab-Notes

We want to create a HomeLab/server running on minimum Virtualization. We can either use KVM Virtualisation or OpenStack Lab (All in One).

## KVM Virtualisation

### Install Debian

Install [Debian from minimal CD](https://www.debian.org/CD/netinst/)

### Install KVM

Refer [KVM Installation](https://wiki.debian.org/KVM#Installation)

Check your connectivity with

```console
virsh --connect qemu:///session version
Compiled against library: libvirt 5.0.0
Using library: libvirt 5.0.0
Using API: QEMU 5.0.0
Running hypervisor: QEMU 3.1.0
```

### Basic Network

We would explore creating the network using

- OpenvSwitch
- Bridge Networking

#### OpenvSwitch

We would use OpenvSwitch for creating a network bridge or a virtual switch.

##### Install OpenvSwitch

Refer [Install OpenvSwitch for Debian](https://docs.openvswitch.org/en/latest/intro/install/distributions/#debian)

##### Setup Basic Network

Once, we have installed `OpenvSwitch`, setup a very basic network using [KVM OpenvSwitch](http://docs.openvswitch.org/en/latest/howto/kvm/)

Mainly, create a bridge named br0 with the following command:

```console
ovs-vsctl add-br br0
```

and then add a port to the bridge for the NIC that you want your guests to communicate over (e.g. eth0)

```console
ovs-vsctl add-port br0 eth0
```

##### Edit libvirt VM XML file

Edit the VM XML file using [Open vSwitch with Libvirt](https://docs.openvswitch.org/en/latest/howto/libvirt/)

### Virtual Machine Creation

#### Using Terraform

If you get error `could not find capabilities for domaintype=kvm`, Ensure that your user is added to kvm

We can use [Terraform Configuration for Creating VM on KVM Virtualisation](https://github.com/bitvijays/terraform-example)

#### Using Virsh

virt-install is a command line tool for creating new KVM , Xen, or Linux container guests using the "libvirt" hypervisor management library.

So, probably, we have install KVM and added the non-root user to the libvirt and libvirtd group.

We can run VM using either non-root user or root user.

If we are using non-root user and defining

```
 --connect=CONNECT
```

Connect to a non-default hypervisor. The default connection is chosen based on the following rules:

If running on a host with the Xen kernel (checks against /proc/xen)

```
 xen
```

If running on a bare metal kernel as root (needed for KVM installs)

```
 qemu:///system
```
If running on a bare metal kernel as non-root

```
 qemu:///session
```

We first tried with running as non-root, however, having permission error while setting up the network, so better to try with running virt-install as a non-root user and using system.

We can also use virt-manager

```shell
 virt-manager --connect 'qemu+ssh://username@hostname/system'
 system for root
 session for non-root
```

Defining VirtualSwitch Network in XML format

```shell
 vi /tmp/ovs-network.xml
 <network>
 <name>ovs-network</name>
 <forward mode='bridge'/>
 <bridge name='ovs-br0'/>
 <virtualport type='openvswitch'/>
 </network>
```

```shell
 virsh net-define /tmp/ovs-network.xml
 Network ovs-network defined from /tmp/ovs-network.xml

 virsh net-start ovs-network
 Network ovs-network started

 virsh net-autostart ovs-network
 Network ovs-network marked as autostarted
```

```shell
 virsh net-list
  Name                 State      Autostart     Persistent
 ----------------------------------------------------------
  default              active     yes           yes
  ovs-network          active     yes           yes
```

[Follow libvirt](http://docs.openvswitch.org/en/latest/howto/libvirt/>)

#### Creating VM

With Openvswitch serving as a bridge with default bridge named ovs-br0 VM can be created by either defining the network like above XML file above

```shell
 virt-install --connect=qemu:///system --name PuppetServer --memory=4096 --vcpus=1 --cdrom=/media/bitvijays/ISO/debian-9.8.0-amd64-DVD-1.iso --os-variant=OS_VARIANT --disk size=50 --graphics vnc,password="password",listen=0.0.0.0 --network=network:ovs-network
```

Log files for ovs (openvswitch) are kept under the folder `/var/log/openvswitch`

```shell
 virt-install --connect=qemu:///system --name PuppetServer --memory=4096 --vcpus=1 --cdrom=/media/bitvijays/ISO/debian-9.8.0-amd64-DVD-1.iso --os-variant=OS_VARIANT --disk size=50 --graphics vnc,password="password",listen=0.0.0.0 --network=bridge:ovs-br0,model=virtio,virtualport_type=openvswitch
```

//Extra-args doesn't work with cdrom and location

```shell
virt-install --connect=qemu:///system --name PuppetServer4 --memory=4096 --vcpus=1 --location http://ftp.uk.debian.org/debian/dists/stable/main/installer-amd64/ --os-variant=OS_VARIANT --disk size=50 --graphics vnc,password="password",listen=0.0.0.0 --network=bridge:ovs-br0,model=virtio,virtualport_type=openvswitch --extra-args="auto=true locale=en_GB priority=critical hostname=puppet01 url=http://192.168.1.51:8001/debian_preseed.cfg"
```

Hostname can't be full domain name, it has to with dot.

OS_VARIANT can be found by using osinfo-query

```shell
 apt-get install  libosinfo-bin
 # List all operating systems
  $ osinfo-query os
   Short ID             | Name       ...
  ----------------------+-----------
   centos-6.0           | CentOS 6.0 ...
   centos-6.1           | CentOS 6.1 ...
```

##### General Options

General configuration parameters that apply to all types of guest installs.

```
 -n NAME , --name=NAME : Name of the new guest virtual machine instance. This must be unique amongst all guests known to the hypervisor on the connection, including those not currently active. To re-define an existing guest, use the virsh(1) tool to shut it down ('virsh shutdown') & delete ('virsh undefine') it prior to running "virt-install".
-r MEMORY , --ram=MEMORY : Memory to allocate for guest instance in megabytes. If the hypervisor does not have enough free memory, it is usual for it to automatically take memory away from the host operating system to satisfy this allocation.
--arch=ARCH : Request a non-native CPU architecture for the guest virtual machine. If omitted, the host CPU architecture will be used in the guest.
--machine=MACHINE : The machine type to emulate. This will typically not need to be specified for Xen or KVM , but is useful for choosing machine types of more exotic architectures.
--vcpus=VCPUS[,maxvcpus=MAX][,sockets=#][,cores=#][,threads=#] : Number of virtual cpus to configure for the guest. If 'maxvcpus' is specified, the guest will be able to hotplug up to MAX vcpus while the guest is running, but will startup with VCPUS .
--description : Human readable text description of the virtual machine. This will be stored in the guests XML configuration for access by other applications.
```

##### Installation Method options

```
 -c CDROM , --cdrom=CDROM : File or device use as a virtual CD-ROM device for fully virtualized guests. It can be path to an ISO image, or to a CDROM device. It can also be a URL from which to fetch/access a minimal boot ISO image. The URLs take the same format as described for the "--location" argument. If a cdrom has been specified via the "--disk" option, and neither "--cdrom" nor any other install option is specified, the "--disk" cdrom is used as the install media.

 -l LOCATION , --location=LOCATION : Distribution tree installtion source. virt-install can recognize certain distribution trees and fetches a bootable kernel/initrd pair to launch the install.
With libvirt 0.9.4 or later, network URL installs work for remote connections. virt-install will download kernel/initrd to the local machine, and then upload the media to the remote host. This option requires the URL to be accessible by both the local and remote host.

 The "LOCATION" can take one of the following forms:

 DIRECTORY
 Path to a local directory containing an installable distribution image
 nfs:host:/path or nfs://host/path : An NFS server location containing an installable distribution image
 http://host/path : An HTTP server location containing an installable distribution image
 ftp://host/path : An FTP server location containing an installable distribution image

 --import : Skip the OS installation process, and build a guest around an existing disk image. The device used for booting is the first device specified via "--disk" or "--filesystem".
 --init=INITPATH : Path to a binary that the container guest will init. If a root "--filesystem" is has been specified, virt-install will default to /sbin/init, otherwise will default to /bin/sh.
 --livecd : Specify that the installation media is a live CD and thus the guest needs to be configured to boot off the CDROM device permanently. It may be desirable to also use the "--nodisks" flag in combination.
 --os-type=OS_TYPE Optimize the guest configuration for a type of operating system (ex. 'linux', 'windows'). This will attempt to pick the most suitable ACPI & APIC settings, optimally supported mouse drivers, virtio, and generally accommodate other operating system quirks.
 By default, virt-install will attempt to auto detect this value from the install media (currently only supported for URL installs). Autodetection can be disabled with the special value 'none'

 See "--os-variant" for valid options.

 --os-variant=OS_VARIANT : Further optimize the guest configuration for a specific operating system variant (ex. 'fedora8', 'winxp'). This parameter is optional, and does not require an "--os-type" to be specified.
 By default, virt-install will attempt to auto detect this value from the install media (currently only supported for URL installs). Autodetection can be disabled with the special value 'none'.

 If the special value 'list' is passed, virt-install will print the full list of variant values and exit. The printed format is not a stable interface, DO NOT PARSE IT .

 Use '--os-variant list' to see the full OS list
```

##### Storage Configuration

```

 --disk=DISKOPTS : Specifies media to use as storage for the guest, with various options. The general format of a disk string is --disk opt1=val1,opt2=val2,...
 To specify media, the command can either be: --disk /some/storage/path,opt1=val1 or explicitly specify one of the following arguments:
 path A path to some storage media to use, existing or not. Existing media can be a file or block device. If installing on a remote host, the existing media must be shared as a libvirt storage volume.
 Specifying a non-existent path implies attempting to create the new storage, and will require specifyng a 'size' value. If the base directory of the path is a libvirt storage pool on the host, the new storage will be created as a libvirt storage volume. For remote hosts, the base directory is required to be a storage pool if using this method.

 size : size (in GB ) to use if creating new storage

 --filesystem : Specifies a directory on the host to export to the guest. The most simple invocation is:
 --filesystem /source/on/host,/target/point/in/guest Which will work for recent QEMU and linux guest OS or LXC containers. For QEMU , the target point is just a mounting hint in sysfs, so will not be automatically mounted.

 --nodisks Request a virtual machine without any local disk storage, typically used for running 'Live CD ' images or installing to network storage (iSCSI or NFS root).
 ```

##### Networking Configuration

```
 -w NETWORK , --network=NETWORK,opt1=val1,opt2=val2 : Connect the guest to the host network. The value for "NETWORK" can take one of 3 formats:
 
 bridge=BRIDGE : Connect to a bridge device in the host called "BRIDGE". Use this option if the host has static networking config & the guest requires full outbound and inbound connectivity to/from the LAN . Also use this if live migration will be used with this guest.
 
 network=NAME : Connect to a virtual network in the host called "NAME". Virtual networks can be listed, created, deleted using the "virsh" command line tool. In an unmodified install of "libvirt" there is usually a virtual network with a name of "default". Use a virtual network if the host has dynamic networking (eg NetworkManager), or using wireless. The guest will be NATed to the LAN by whichever connection is active.
 
 user : Connect to the LAN using SLIRP . Only use this if running a QEMU guest as an unprivileged user. This provides a very limited form of NAT. If this option is omitted a single NIC will be created in the guest. If there is a bridge device in the host with a physical interface enslaved, that will be used for connectivity. Failing that, the virtual network called "default" will be used. This option can be specified multiple times to setup more than one NIC .

 Other available options are:

 model
 Network device model as seen by the guest. Value can be any nic model supported by the hypervisor, e.g.: 'e1000', 'rtl8139', 'virtio', ...
 mac
 Fixed MAC address for the guest; If this parameter is omitted, or the value "RANDOM" is specified a suitable address will be randomly generated. For Xen virtual machines it is required that the first 3 pairs in the  MAC address be the sequence '00:16:3e', while for QEMU or KVM virtual machines it must be '52:54:00'.

 --nonetworks
 Request a virtual machine without any network interfaces.
```

##### Graphics Configuration

If no graphics option is specified, "virt-install" will default to '--graphics vnc' if the DISPLAY environment variable is set, otherwise '--graphics none' is used.

```
 --graphics TYPE ,opt1=arg1,opt2=arg2,... Specifies the graphical display configuration. This does not configure any virtual hardware, just how the guest's graphical display can be accessed. Typically the user does not need to specify this option, virt-install will try and choose a useful default, and launch a suitable connection.

 General format of a graphical string is

 --graphics TYPE,opt1=arg1,opt2=arg2,...

 For example:
 --graphics vnc,password=foobar
 The supported options are:
 type
 The display type. This is one of:
 vnc

 Setup a virtual console in the guest and export it as a VNC server in the host. Unless the "port" parameter is also provided, the VNC server will run on the first free port number at 5900 or above. The actual VNC display allocated can be obtained using the "vncdisplay" command to "virsh" (or virt-viewer(1) can be used which handles this detail for the use).


 port : Request a permanent, statically assigned port number for the guest console. This is used by 'vnc' and 'spice'
 tlsport : Specify the spice tlsport.
 listen : Address to listen on for VNC/Spice connections. Default is typically 127.0.0.1 (localhost only), but some hypervisors allow changing this globally (for example, the qemu driver default can be changed in /etc/libvirt/qemu.conf). Use 0.0.0.0 to allow access from other machines. This is use by 'vnc' and 'spice'
 password : Request a VNC password, required at connection time. Beware, this info may end up in virt-install log files, so don't use an important password. This is used by 'vnc' and 'spice'

 --noautoconsole : Don't automatically try to connect to the guest console. The default behaviour is to launch a VNC client to display the graphical console, or to run the "virsh" "console" command to display the text console. Use of this parameter will disable this behaviour.
```

##### Device Options

```
--host-device=HOSTDEV
Attach a physical host device to the guest. Some example values for HOSTDEV:
--host-device pci_0000_00_1b_0
A node device name via libvirt, as shown by 'virsh nodedev-list'
--host-device 001.003
USB by bus, device (via lsusb).
--host-device 0x1234:0x5678
USB by vendor, product (via lsusb).
--host-device 1f.01.02
PCI device (via lspci).
```

##### Miscellaneous Options

```
 --autostart
 Set the autostart flag for a domain. This causes the domain to be started on host boot up.
 --print-xml
 If the requested guest has no install phase (--import, --boot), print the generated XML instead of defining the guest. By default this WILL do storage creation (can be disabled with --dry-run).
 If the guest has an install phase, you will need to use --print-step to specify exactly what XML output you want. This option implies --quiet.

 --print-step
 Acts similarly to --print-xml, except requires specifying which install step to print XML for. Possible values are 1, 2, 3, or all. Stage 1 is typically booting from the install media, and stage 2 is typically the  final guest config booting off hardisk. Stage 3 is only relevant for windows installs, which by default have a second install stage. This option implies --quiet.
 --noreboot
 Prevent the domain from automatically rebooting after the install has completed.
 --wait=WAIT
 Amount of time to wait (in minutes) for a VM to complete its install. Without this option, virt-install will wait for the console to close (not neccessarily indicating the guest has shutdown), or in the case of  --noautoconsole, simply kick off the install and exit. Any negative value will make virt-install wait indefinitely, a value of 0 triggers the same results as noautoconsole. If the time limit is exceeded, virt-install simply exits, leaving the virtual machine in its current state.
 --force
 Prevent interactive prompts. If the intended prompt was a yes/no prompt, always say yes. For any other prompts, the application will exit.
 --dry-run
 Proceed through the guest creation process, but do NOT create storage devices, change host device configuration, or actually teach libvirt about the guest. virt-install may still fetch install media, since this is required to properly detect the OS to install.
 -q, --quiet
 Only print fatal error messages.
 -d, --debug
 Print debugging information to the terminal when running the install process. The debugging information is also stored in "$HOME/.virtinst/virt-install.log" even if this parameter is omitted.
```

## VirtualBox

```shell
 VBoxManage.exe createvm --name Debian_Puppet --ostype Debian_64 --register

 VBoxManage.exe createmedium disk --filename "C:\Users\u_bitvijays\VirtualBox VMs\Debian_Puppet\Debian_Puppet.vdi" --size 40000

 VBoxManage storagectl Debian_Puppet --name SATA --add SATA --controller IntelAhci
 VBoxManage storageattach Debian_Puppet --storagectl SATA --port 0 --device 0 --type hdd --medium "C:\Users\u_bitvijays\VirtualBox VMs\Debian_Puppet\Debian_Puppet.vdi"

 VBoxManage storagectl Debian_Puppet --name IDE --add ide
 VBoxManage storageattach Debian_Puppet --storagectl IDE --port 0 --device 0 --type dvddrive --medium "C:\Users\u_bitvijays\Downloads\Dump\Setups\debian-9.9.0-amd64-netinst.iso"

 VBoxManage modifyvm Debian_Puppet --memory 4096 --vram 16

 VBoxManage unattended install Debian_Puppet --user=bitvijays --password=Passw0rd! --country=UK --language=en_US --locale=en_US --hostname=server01.bitvijays.local --iso="C:\Users\u_bitvijays\Downloads\Dump\Setups\debian-9.9.0-amd64-netinst.iso" --install-additions --package-selection-adjustment=minimal

 VBoxManage modifyvm "Debian_Puppet" --nic2 hostonly

 VBoxManage modifyvm "Debian_Puppet" --hostonlyadapter2 vboxnet0
 ```

In the Debian Preseed file ( C:\Program Files\Oracle\VirtualBox\UnattendedTemplates )

Add the below line

```
 ##bitvijays

 d-i mirror/http/hostname string ftp.uk.debian.org
 d-i mirror/http/directory string /debian
```

# Puppet Master

- Best way to learn puppet is to download [Puppet Learning VM](https://puppet.com/download-learning-vm) and perform the quests.

- Enable the [Puppet platform on APT](https://puppet.com/docs/puppet/latest/puppet_platform.html#task-383)

- Basically visit [Puppet Repo](https://apt.puppetlabs.com/) and choose latest puppet server release for your operating system. I currently run Debian 9 stretch, so for me it's [Xenial](https://apt.puppetlabs.com/puppet6-release-xenial.deb)

- Setup the permanent IP address using /etc/network/interfaces

## Install PuppetServer

```shell
 cd /tmp; wget https://apt.puppetlabs.com/puppet6-release-xenial.deb --no-check-certificate; dpkg -i /tmp/puppet6-release-xenial.deb; apt-get update; apt-get install puppetserver; /opt/puppetlabs/bin/puppetserver ca setup; systemctl start puppetserver; apt-get install locate man vim
```

We would utilise `razor <https://github.com/puppetlabs/razor-server>`_to do most of the automatic provision.

`Installation Step of razor-server <https://github.com/puppetlabs/razor-server/wiki/Installation>`_

1. Database setup : Install puppetlabs-postgresql

::

 class { 'postgresql::globals':
   manage_package_repo => true,
   version             => '9.2',
 }->

 class { 'postgresql::server': }

 postgresql::server::db { 'razor':
   user     => 'razor',
   password => postgresql_password('razor', 'secret'),
 }

Puppet
======

Bolt
----

Bolt is an open-source remote task runner; connects directly to remote nodes with SSH or WinRM without any agent installation on the target box. Can be used to automate tasks that you need to perform on your infrastructure on an ad hoc basis, such as troubleshooting, deploying an application, stopping and starting services, and upgrading a database schema.

```shell
 bolt --help | more
 Usage: bolt <subcommand> <action> [options]
 
 Available subcommands:
  bolt command run <command>       Run a command remotely
  bolt file upload <src> <dest>    Upload a local file
  bolt script run <script>         Upload a local script and run it remotely
  bolt apply <manifest>            Apply Puppet manifest code

 where [options] are:
     -n, --nodes NODES                Identifies the nodes to target.
 Authentication:
     -u, --user USER                  User to authenticate as
     -p, --password [PASSWORD]        Password to authenticate with. Omit the value to prompt for the password.
 Escalation:
         --run-as USER                User to run as using privilege escalation
         --sudo-password [PASSWORD]   Password for privilege escalation. Omit the value to prompt for the password.
 Display:
         --format FORMAT              Output format to use: human or json
```

## OpenWrt

Let's say that you have a router running OpenWrt, however it requires MAC Spoofing. One of the way to do it is by logging into it and performing

```shell

 root@OpenWrt:~# ifconfig eth1 down
 root@OpenWrt:~# ifconfig eth1 hw ether XX:XX:XX:XX:XX:XX
 root@OpenWrt:~# ifconfig eth1 up
 root@OpenWrt:~# ifconfig eth1
```

However, this would be temporary. If we want the MAC address to be set when system boots up, we can use [init scripts](https://openwrt.org/docs/techref/initscripts)

Edit `/etc/init.d/clonemac`

```bash
 START=94
 STOP=15

 start() {
     ifconfig eth1 down
     ifconfig eth1 hw ether XX:XX:XX:XX:XX:XX
     ifconfig eth1 up
 }

 stop() {
     echo "Stop."
 }
```

Make the script executable, then we can change the MAC address simply by this:

```shell

 root@OpenWrt:~# /etc/init.d/clonemac start
```

To execute the script automatically on system boot, we need to enable it:

```shell
 root@OpenWrt:~# /etc/init.d/clonemac enable
```

This will create a symbolic link to the clonemac script in /etc/rc.d. Reboot the router and you will find the new MAC address be automatically used.

## Dump

Here We are creating a bridge br0 and then adding the ethernet port to the bridge. Basically, the interface would get a DHCP ip ?? -- This would probably break your network as we would add eth0/ethernet interface to the br0 and routing has to be routed via br0. change default gw etc.
- So, flush the IP of the ethernet device by

  ```shell
  ip addr flush dev eth0
  ```

  And also flush all the routes
  
  ```shell
  ip route flush all ( it would remove all the routes) --!!
  ```

  Now, we can do

  ```shell
  dhclient br0
  ```

  to get the ip address and add the default gateway !

or we can do it like

https://forum.netgate.com/topic/122148/installing-pfsense-on-kvm-with-openvswitch-a-somewhat-complete-guide

Edit /etc/network/interfaces

```shell
 source /etc/network/interfaces.d/*

 # The loopback network interface
 auto lo
 iface lo inet loopback

 # The primary network interface
 auto ens3
 iface ens3 inet manual

 auto OVSBridge
 iface OVSBridge inet static
 address 192.168.122.150
 netmask 255.255.255.0
 gateway 192.168.122.1

 dns-nameservers 8.8.8.8
```

and

```shell
 sudo ovs-vsctl add-port OVSBridge <physical interface=""> tag=100 trunk=200 && sudo reboot now</physical>
```

This will add the port to the OVS, and you will lose all connectivity. This will also reboot the server. After reboot, it should come back with the IP above. If it doesn't, grab a keyboard, plug it in the server and try to figure out why…
