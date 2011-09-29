
use strict;
use warnings;

use Module::Build 0.3601;


my %module_build_args = (
  'build_requires' => {
    'Module::Build' => '0.3601'
  },
  'configure_requires' => {
    'Module::Build' => '0.3601'
  },
  'dist_abstract' => 'Parse the output of Unix "netstat" command',
  'dist_author' => [
    'Steven Haryanto <stevenharyanto@gmail.com>'
  ],
  'dist_name' => 'Parse-Netstat',
  'dist_version' => '0.01',
  'license' => 'perl',
  'module_name' => 'Parse::Netstat',
  'recommends' => {},
  'recursive_test_files' => 1,
  'requires' => {
    'Exporter::Lite' => '0',
    'Sub::Spec' => '1.0.4',
    'Test::More' => '0.96',
    'perl' => '5.010000'
  },
  'script_files' => []
);


my $build = Module::Build->new(%module_build_args);

$build->create_build_script;
