# frozen_string_literal: true

virtualbox = system("command -v VBoxManage >/dev/null 2>&1")

Vagrant.configure("2") do |config|
  config.vm.define "linux" do |linux|
    linux.vm.hostname = "policyflow-linux"
    linux.ssh.username = "vagrant"
    linux.ssh.insert_key = false

    if virtualbox
      linux.vm.box = "bento/ubuntu-24.04"
      linux.vm.provider "virtualbox" do |vb|
        vb.name = "policyflow-linux"
        vb.memory = 2048
        vb.cpus = 2
      end
    else
      linux.vm.provider "docker" do |docker|
        docker.build_dir = "vagrant/linux"
        docker.has_ssh = true
        docker.remains_running = true
        docker.name = "policyflow-linux"
      end
    end
  end
end
