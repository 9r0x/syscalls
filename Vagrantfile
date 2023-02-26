VAGRANT_BOX_MEMORY = 4096
VAGRANT_BOX_CPUS = 4

Vagrant.configure("2") do |config|

  config.vm.box = "debian/bullseye64"

  # Set the Vagrant box's RAM
  config.vm.provider :virtualbox do |vb|
    vb.memory = VAGRANT_BOX_MEMORY
    vb.cpus = VAGRANT_BOX_CPUS
  end

  config.vm.provision :shell, :inline => %Q{
    sudo apt-get update
    sudo apt-get install make build-essential emacs zsh lldb clang curl git -y
  }
end