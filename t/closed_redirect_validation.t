#!/usr/bin/env perl
use Mojolicious::Lite;
use Test::Mojo;
use Test::More;

app->secrets(['abcdefghijklmnopqrstuvwxyz']);

plugin 'ClosedRedirect';

my $fail;
app->hook(
  on_open_redirect_attack => sub {
    my ($field, $url, $msg) = @_;
    $msg //= '';
    $fail = "Fail: $field:$url - $msg";
  }
);

# Check for signed redirect parameter
get '/signed' => sub {
  my $c = shift;
  my $v = $c->validation;

  $v->required('fwd')->closed_redirect('signed');

  return $c->render(text => $v->param('fwd')) unless $v->has_error;

  my $fail = $v->param('fwd') // 'no';
  $fail .= '-' . join(',', @{$v->error('fwd')});
  return $c->render(text => 'fail-' . $fail, status => 403);
} => 'signed';


# Check for local redirect parameter
get '/local' => sub {
  my $c = shift;
  my $v = $c->validation;

  $v->required('fwd')->closed_redirect('local');

  return $c->render(text => $v->param('fwd')) unless $v->has_error;

  my $fail = $v->param('fwd') // 'no';
  $fail .= '-' . join(',', @{$v->error('fwd')});
  return $c->render(text => 'fail-' . $fail, status => 403);
} => 'local';

my $t = Test::Mojo->new;

# Check signed
$t->get_ok('/signed?fwd=hallo')
  ->status_is(403)
  ->content_is('fail-no-closed_redirect,Redirect is invalid,signed');
is($fail, 'Fail: fwd:hallo - Redirect is invalid', 'Failed');
$fail = '';

$t->get_ok('/signed?fwd=/mypath?crto=a4538583e3c0a534f3863050804c746a9bd92a2f')
  ->status_is(200)
  ->content_is('/mypath');
ok(!$fail, 'No fail');

# Only one fwd is fine!
$t->get_ok('/signed?fwd=/mypath?crto=a4538583e3c0a534f3863050804c746a9bd92a2f'.
             '&fwd=/mypath?crto=a4538583e3c0a534f3863050804c746a9bd92a2f')
  ->status_is(403)
  ->content_is('fail-no-closed_redirect,Redirect is defined multiple times,signed');
is($fail, 'Fail: fwd:/mypath?crto=a4538583e3c0a534f3863050804c746a9bd92a2f - Redirect is defined multiple times', 'Failed');
$fail = '';

my $surl = app->signed_url_for('http://example.com/cool.php');
is($surl, 'http://example.com/cool.php?crto=9809dfc8b938498b70e3b0a290ba40109d914f71', 'Signed URL is fine');

$t->get_ok('/signed?fwd=' . $surl)
  ->status_is(200)
  ->content_is('http://example.com/cool.php')
  ;
ok(!$fail, 'No fail');

# Fail
$t->get_ok('/signed?fwd=' . $surl . 'g')
  ->status_is(403)
  ->content_is('fail-no-closed_redirect,Redirect is invalid,signed')
  ;
is($fail, 'Fail: fwd:http://example.com/cool.php?crto=9809dfc8b938498b70e3b0a290ba40109d914f71g - Redirect is invalid', 'Hook');
$fail = '';

# Check local
$t->get_ok('/local?fwd=/tree')
  ->status_is(200)
  ->content_is('/tree');
ok(!$fail, 'No hook');

$t->get_ok('/local?fwd=' . app->url_for('signed')->query({ q => 123 }))
  ->status_is(200)
  ->content_is('/signed?q=123');
ok(!$fail, 'No hook');

$t->get_ok('/local?fwd=//tree')
  ->status_is(403)
  ->content_is('fail-no-closed_redirect,Redirect is invalid,local');
is($fail, 'Fail: fwd://tree - Redirect is invalid', 'Hook');
$fail = '';

# Signed URL is invalid, too
$t->get_ok('/local?fwd=' . $surl)
  ->status_is(403)
  ->content_is('fail-no-closed_redirect,Redirect is invalid,local');
is($fail, 'Fail: fwd:http://example.com/cool.php?crto=9809dfc8b938498b70e3b0a290ba40109d914f71 - Redirect is invalid', 'Hook');
$fail = '';

# Fail required
$t->get_ok('/local?fwd=')
  ->status_is(403)
  ->content_is('fail-no-required')
  ;
ok(!$fail, 'No hook');

done_testing;
__END__

