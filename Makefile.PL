#!/usr/bin/env perl
use 5.010001;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
  NAME         => 'Mojolicious::Plugin::ClosedRedirect',
  AUTHOR       => 'Nils Diewald',
  ABSTRACT     => 'Defend Open Redirect Attacks',
  VERSION_FROM => 'lib/Mojolicious/Plugin/ClosedRedirect.pm',
  BUILD_REQUIRES => {
    'Test::More' => 0
  },
  PREREQ_PM => {
    'Mojolicious' => 3.43
    },
  META_MERGE   => {
    requires  => { perl => '5.010001' },
  },
  MIN_PERL_VERSION => '5.010001',
  test => {TESTS => 't/*.t'}
);

