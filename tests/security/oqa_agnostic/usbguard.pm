# SUSE's openQA tests
#
# Copyright SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Package: usbguard usbguard-tools usbutils
# Summary: Verify the usbguard USB-access-control engine on any SUT
# - Install usbguard with install_package (portable across zypper/dnf/apt)
# - Run the usbguard pytest suite from data/security/openqa_agnostic/python/
#   usbguard via agnosticTestRunner
#
# New, portable counterpart to tests/security/usbguard/usbguard.pm. It keeps the
# portable core (daemon active + device-policy flip + audit-log record) and skips
# device-specific or environment-specific checks instead of failing on
# minimal/VM images.
#
# Maintainer: QE Security <none@suse.de>
# Tags: poo#210159

use Mojo::Base 'opensusebasetest';
use testapi;
use serial_terminal 'select_serial_terminal';
use package_utils 'install_package';
use agnosticTestRunner;

my %runner_args = (
    language => 'python',
    name => 'usbguard',
    domain => 'security',
    run_timeout => 900,
);

sub run {
    my ($self) = @_;
    select_serial_terminal;
    # install_package abstracts zypper/dnf/apt, so the same data runs on any distro.
    # usbguard does not need a reboot after install, so continue in place.
    install_package('usbguard usbguard-tools usbutils', trup_continue => 1);
    # any reboot on transactional systems leaves the VGA root console selected
    select_serial_terminal;

    my $runner = agnosticTestRunner->new(%runner_args);
    $runner->setup()->run_test()->parse_results()->cleanup();
}

1;
