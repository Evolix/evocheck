# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant::DEFAULT_SERVER_URL.replace('https://vagrantcloud.com')

# Load ~/.VagrantFile if exist, permit local config provider
vagrantfile = File.join("#{Dir.home}", '.VagrantFile')
load File.expand_path(vagrantfile) if File.exists?(vagrantfile)

Vagrant.configure('2') do |config|
  config.vm.synced_folder "./", "/vagrant", type: "rsync", rsync__exclude: [ '.vagrant', '.git' ]
  config.ssh.shell="/bin/sh"

  $deps = <<SCRIPT
rm -f /usr/share/scripts/evocheck.sh
ln -s /vagrant/evocheck.sh /usr/share/scripts/evocheck.sh
cat >/etc/evocheck.cf <<EOF
IS_CUSTOMSUDOERS=0
IS_VARTMPFS=0
IS_USRRO=0
IS_TMPNOEXEC=0
IS_SSHALLOWUSERS=0
IS_ALERT5MINIFW=0
IS_MINIFW=0
IS_MINIFWPERMS=0
IS_EVOBACKUP=0
IS_MUNINRUNNING=0
IS_EVOLINUXSUDOGROUP=0
IS_LOG2MAILSYSTEMDUNIT=0
IS_LISTUPGRADE=0
IS_EVOMAINTENANCECONF=0
EOF
SCRIPT

  config.vm.define :evocheck do |node|
    node.vm.hostname = "evocheck.example.com"
    node.vm.box = "evolix/evolinux"

    node.vm.provision "deps", type: "shell", :inline => $deps

  end

end
