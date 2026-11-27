# PolicyFlow

PolicyFlow is an Ansible collection that checks Linux, Windows, macOS, and firewalls against a policy you choose, writes a PDF report, and can apply firewall and access-control rules you define.

The repository is [cybersecmorocco/policyflow-automation](https://github.com/cybersecmorocco/policyflow-automation). The collection id is `policyflow.automation`.

## The idea

Security teams repeat the same two jobs. They ask whether a machine or a firewall still matches the rules it should be running, and they push a firewall or access change when it does not. PolicyFlow keeps both jobs in one collection.

You put the machines and the firewalls in an Ansible inventory. You fill in a short config: which frameworks to check, whether the report includes every machine, optional email settings, and any firewall rules of your own. A check playbook only reads. A configure playbook applies firewall best practice, access control, and those custom rules.

The collection ships its own Ansible modules where a built-in module cannot do the job. A missing module is a reason to write one. It is not a reason to drop a check, a report, or a rule.

## What a check covers

On Linux, Windows, and macOS the check compares the host with these frameworks:

- CIS
- DISA STIG
- NIST SP 800-53
- PCI-DSS
- HIPAA
- NIS2

HIPAA and NIS2 are reported as mapped technical controls: access, logging, firewall policy, encryption settings, and account hygiene. A passing control means that setting matched. The PDF does not issue a legal certification.

On a firewall, the check compares the running configuration with the rules that should be there. Each firewall type is its own implementation. Host firewalls and appliance-style firewalls do not share one module.

## The report

The check writes a PDF.

- The first page is a dashboard: machines in scope, an overall score, pass, fail, and waived counts, and a score for each framework.
- The next pages summarize the fleet, one row per machine.
- When the config asks for detail, each machine gets its own pages: control, framework, result, actual value, and expected value.

The check writes that dashboard to `reports/policyflow.pdf`. If the config includes email settings, the playbook sends that PDF. If the email block is absent, the file is still written and nothing is sent.

## Configure

The same collection can set the machines to a firewall and access-control baseline, then add rules you wrote. A custom rule is data in the config, for example an allow on a port from a source you name. Configure does not silently rewrite every failed compliance control. It applies the firewall and access rules the config declares.

## How a run is started

The inputs stay small. Frameworks, report detail, optional email, and your rules live in `config/policyflow.yml`. Inventory selects the machines. Two playbooks use that file:

```bash
ansible-playbook playbooks/check.yml -i inventories/vagrant.ini
ansible-playbook playbooks/configure.yml -i inventories/vagrant.ini
```

Check only reads the machine. Configure in this release validates the rules and does not change the machine. Applying those rules comes in a later release.

## Linux lab

Install this, then start the box:

1. Install [Vagrant](https://developer.hashicorp.com/vagrant/install).
2. Install VirtualBox, or install Docker if you already work with containers. When VirtualBox is absent, `vagrant up` builds the Linux machine from `vagrant/linux`.
3. Install Ansible. ansible-core 2.16 or newer.

From a clean checkout:

```bash
vagrant up
scripts/write-inventory.sh
ansible-playbook playbooks/check.yml -i inventories/vagrant.ini
```

Open `reports/policyflow.pdf`. The first page shows the machines in the run, the score, and the pass, fail, and waived counts.

`vagrant up` starts the machine named `linux`. The script writes `inventories/vagrant.ini` from `vagrant ssh-config`. That file stays off the git history because it contains a path to a local key.

The `Vagrantfile` will gain a machine per target family and per firewall type: Windows, macOS, and each firewall implementation. Where a firewall already publishes a container image, the lab starts that container. Vagrant remains the single way to bring the lab up.

The macOS guest follows the Vagrant box pattern published by [ramsey/macos-vagrant-box](https://github.com/ramsey/macos-vagrant-box): a VirtualBox box, a `vagrant` user, and SSH. It is used only in line with the [Apple software license](https://www.apple.com/legal/sla/). The guest is started on a Mac host. The published Ramsey boxes go through Catalina. A newer macOS lab box is built with the same [macinbox](https://github.com/bacongravy/macinbox) method.

## Status

The Linux check writes `reports/policyflow.pdf`. Windows, macOS, the other firewall types, and applying rules are still open on the project board.
