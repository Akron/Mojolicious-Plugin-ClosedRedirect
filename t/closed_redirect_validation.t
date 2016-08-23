#!/usr/bin/env perl
use Mojolicious::Lite;
use Test::Mojo;
use Test::More;

app->secrets(['abcdefghijklmnopqrstuvwxyz']);

plugin 'ClosedRedirect';

get '/mypath' => sub {
  my $c = shift;
  my $v = $c->validation;

  $v->required('return_url')->closed_redirect;

  return $c->render(text => 'okay') unless $v->has_error;
  return $c->render(text => 'fail');
} => 'myname';

my $t = Test::Mojo->new;

$t->get_ok('/mypath?return_url=hallo')
  ->status_is(200)
  ->content_is('fail');

$t->get_ok('/mypath?return_url=/mypath?crto=a4538583e3c0a534f3863050804c746a9bd92a2f')
  ->status_is(200)
  ->content_is('okay');


done_testing;
__END__
