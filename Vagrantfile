VAGRANT_BOX_MEMORY = 10240
VAGRANT_BOX_CPUS = 6

Vagrant.configure("2") do |config|

  config.vm.box = "debian/bullseye64"
  config.disksize.size = '50GB'

  # Set the Vagrant box's RAM
  config.vm.provider :virtualbox do |vb|
    vb.memory = VAGRANT_BOX_MEMORY
    vb.cpus = VAGRANT_BOX_CPUS
  end

  config.vm.provision :shell, :inline => %Q{
    sudo resize2fs -p -F /dev/sda1
    sudo apt-get update
    sudo apt-get install make build-essential lldb clang curl git wget xz-utils gpg tar gawk patch build-essential libncurses-dev bison flex bc openssl libssl-dev libelf-dev dwarves -y
    su - vagrant -c 'cd $HOME && wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.2.10.tar.xz && tar xf linux-6.2.10.tar.xz && rm linux-6.2.10.tar.xz && cd linux-6.2.10 && cp -v /boot/config-* .config && yes "" | make oldconfig && scripts/config --set-str CONFIG_SYSTEM_TRUSTED_KEYS ""'
  }
end
