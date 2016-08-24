#!/usr/bin/env perl
use Mojolicious::Lite;
use Test::Mojo;
use Test::More;

app->secrets(['abcdefghijklmnopqrstuvwxyz']);

plugin 'ClosedRedirect';

get '/mypath' => sub {
  my $c = shift;
  my $v = $c->validation;

  $v->required('fwd')->closed_redirect('signed');

  return $c->render(text => $v->param('fwd')) unless $v->has_error;

  my $fail = $v->param('fwd') // 'no';
  $fail .= '-' . join(',', @{$v->error('fwd')});
  return $c->render(text => 'fail-' . $fail);
} => 'myname';

my $t = Test::Mojo->new;

$t->get_ok('/mypath?fwd=hallo')
  ->status_is(200)
  ->content_is('fail-no-closed_redirect,Redirect URL is invalid,signed');

$t->get_ok('/mypath?fwd=/mypath?crto=a4538583e3c0a534f3863050804c746a9bd92a2f')
  ->status_is(200)
  ->content_is('/mypath');

# Only one fwd is fine!
$t->get_ok('/mypath?fwd=/mypath?crto=a4538583e3c0a534f3863050804c746a9bd92a2f'.
             '&fwd=/mypath?crto=a4538583e3c0a534f3863050804c746a9bd92a2f')
  ->status_is(200)
  ->content_is('fail-no-closed_redirect,Only one redirect URL allowed,signed');


done_testing;
__END__
