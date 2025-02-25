# SUSE's openQA tests
#
# Copyright 2024-2025 SUSE LLC
# SPDX-License-Identifier: FSFAP

# Package: skopeo
# Summary: Upstream skopeo integration tests
# Maintainer: QE-C team <qa-c@suse.de>

use Mojo::Base 'containers::basetest';
use testapi;
use serial_terminal qw(select_serial_terminal);
use utils qw(script_retry);
use containers::common;
use Utils::Architectures qw(is_x86_64);
use containers::bats;
use version_utils qw(is_sle is_sle_micro);

my $test_dir = "/var/tmp";
my $skopeo_version = "";

sub run_tests {
    my %params = @_;
    my ($rootless, $skip_tests) = ($params{rootless}, $params{skip_tests});

    return if ($skip_tests eq "all");

    my $log_file = "skopeo-" . ($rootless ? "user" : "root") . ".tap";

    # Upstream script gets GOARCH by calling `go env GOARCH`.  Drop go dependency for this only use of go
    my $goarch = script_output "podman version -f '{{.OsArch}}' | cut -d/ -f2";
    assert_script_run "sed -i 's/arch=.*/arch=$goarch/' systemtest/010-inspect.bats";

    # Default quay.io/libpod/registry:2 image used by the test only has amd64 image
    my $registry = is_x86_64 ? "" : "docker.io/library/registry:2";

    my %_env = (
        BATS_TMPDIR => "/var/tmp",
        SKOPEO_BINARY => "/usr/bin/skopeo",
        SKOPEO_TEST_REGISTRY_FQIN => $registry,
    );
    my $env = join " ", map { "$_=$_env{$_}" } sort keys %_env;

    assert_script_run "echo $log_file .. > $log_file";
    my $ret = script_run "env $env bats --tap systemtest | tee -a $log_file", 1200;

    my @skip_tests = split(/\s+/, get_var('SKOPEO_BATS_SKIP', '') . " " . $skip_tests);
    patch_logfile($log_file, @skip_tests);
    parse_extra_log(TAP => $log_file);

    return ($ret);
}

sub run {
    my ($self) = @_;
    select_serial_terminal;

    install_bats;
    enable_modules if is_sle;

    # Install tests dependencies
    my @pkgs = qw(apache2-utils jq openssl podman skopeo);
    install_packages(@pkgs);

    $self->bats_setup;

    record_info("skopeo version", script_output("skopeo --version"));
    record_info("skopeo package version", script_output("rpm -q skopeo"));

    assert_script_run "cd $test_dir";

    # Download skopeo sources
    $skopeo_version = script_output "skopeo --version  | awk '{ print \$3 }'";
    script_retry("curl -sL https://github.com/containers/skopeo/archive/refs/tags/v$skopeo_version.tar.gz | tar -zxf -", retry => 5, delay => 60, timeout => 300);
    assert_script_run "cd $test_dir/skopeo-$skopeo_version/";

    my $errors = run_tests(rootless => 1, skip_tests => get_var('SKOPEO_BATS_SKIP_USER', ''));

    select_serial_terminal;
    assert_script_run("cd $test_dir/skopeo-$skopeo_version/");

    $errors += run_tests(rootless => 0, skip_tests => get_var('SKOPEO_BATS_SKIP_ROOT', ''));

    die "Tests failed" if ($errors);
}

sub cleanup() {
    assert_script_run "cd ~";
    script_run("rm -rf $test_dir/skopeo-$skopeo_version/");
    bats_post_hook;
}

sub post_fail_hook {
    my ($self) = @_;
    cleanup();
    $self->SUPER::post_fail_hook;
}

sub post_run_hook {
    my ($self) = @_;
    cleanup();
    $self->SUPER::post_run_hook;
}

1;
