#!/usr/bin/env perl
use Mojolicious::Lite;
use Test::Mojo;
use Test::More;

app->secrets(['abcdefghijklmnopqrstuvwxyz']);

plugin 'ClosedRedirect';

get '/mypath' => sub {
  return shift->render(text => 'test');
} => 'myname';

get '/my/:second/path' => sub {
  return shift->render(text => 'test');
} => 'myname2';

my $t = Test::Mojo->new;

my $app = $t->app;
my $c = $app->build_controller;

my $pure = '/mypath';
my $fine = $pure . '?crto=afdac42addf2ac99';
is($app->signed_url_for('myname'), $fine, 'signed url');
is($c->signed_url_for('myname'), $fine, 'signed url');

# Set correct
ok($c->param(return_url => $fine), 'Set parameter');
ok($c->closed_redirect_to('return_url'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');

# Set false
ok($c->param(return_url => substr($fine, 1)), 'Set parameter');
ok(!$c->closed_redirect_to('return_url'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');

# Set false
ok($c->param(return_url => substr($fine, 0, -1)), 'Set parameter');
ok(!$c->closed_redirect_to('return_url'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');

# Set correct
ok($c->param(return_url => $fine), 'Set parameter');
ok($c->closed_redirect_to('return_url'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');

# ---

$pure = '/my/peter/path';
$fine = $pure . '?crto=08c996d66b0967bf';

is($app->signed_url_for('myname2', second => 'peter'), $fine, 'signed url');
is($c->signed_url_for('myname2', second => 'peter'), $fine, 'signed url');

# Set correct
ok($c->param(return_url_2 => $fine), 'Set parameter');
ok($c->closed_redirect_to('return_url_2'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');

# Set false
ok($c->param(return_url_2 => substr($fine, 1)), 'Set parameter');
ok(!$c->closed_redirect_to('return_url_2'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');

# Set false
ok($c->param(return_url_2 => substr($fine, 0, -1)), 'Set parameter');
ok(!$c->closed_redirect_to('return_url_2'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');
# is($c->flash('alert'), 'An Open Redirect attack was detected', 'Flash alert');

# Set correct
ok($c->param(return_url_2 => $fine), 'Set parameter');
ok($c->closed_redirect_to('return_url_2'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');


# ---


$pure = '/mypath?test=hmm';
$fine = $pure . '&crto=f3431923ba42d7c2';

is($app->signed_url_for($app->url_for('myname')->query({ test => 'hmm' })), $fine, 'signed url');
is($c->signed_url_for($c->url_for('myname')->query({ test => 'hmm' })), $fine, 'signed url');

# Set correct
ok($c->param(redirect_to => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');

# Set false
ok($c->param(redirect_to => substr($fine, 1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');

# Set false
ok($c->param(redirect_to => substr($fine, 0, -1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');

# Set correct
ok($c->param(redirect_to => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');


# ---


$pure = 'http://example.com/';
$fine = $pure . '?crto=bbde52f856a13f49';
is($app->signed_url_for('http://example.com/'), $fine, 'signed url');
is($c->signed_url_for('http://example.com/'), $fine, 'signed url');

# Set correct
ok($c->param(redirect_to_2 => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to_2'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');

# Set false
ok($c->param(redirect_to_2 => substr($fine, 1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to_2'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');

# Set false
ok($c->param(redirect_to_2 => substr($fine, 0, -1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to_2'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');

# Set correct
ok($c->param(redirect_to_2 => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to_2'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');


# ---

$pure = 'http://example.com/?name=test#age';
$fine = 'http://example.com/?name=test&crto=98bfbe150f0cf587#age';
is($app->signed_url_for($pure), $fine, 'signed url');
is($c->signed_url_for($pure), $fine, 'signed url');

# Set correct
ok($c->param(redirect_to_3 => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to_3'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');

# Set false
ok($c->param(redirect_to_3 => substr($fine, 1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to_3'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');

# Set false
ok($c->param(redirect_to_3 => substr($fine, 0, -1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to_3'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');

# Set correct
ok($c->param(redirect_to_3 => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to_3'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');


# ---


my $base = 'http://example.com/?name=test&crto=abcdefhhjgjhghjg#age';
$pure = 'http://example.com/?name=test#age';
$fine = 'http://example.com/?name=test&crto=98bfbe150f0cf587#age';
is($app->signed_url_for($base), $fine, 'signed url');
is($c->signed_url_for($base), $fine, 'signed url');

# Set correct
ok($c->param(redirect_to_3 => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to_3'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');

# Set false
ok($c->param(redirect_to_3 => substr($fine, 1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to_3'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');

# Set false
ok($c->param(redirect_to_3 => substr($fine, 0, -1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to_3'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');

# Set correct
ok($c->param(redirect_to_3 => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to_3'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');

my $query_test = 'http://example.com/?name=test';

is($app->signed_url_for($query_test), 'http://example.com/?name=test&crto=b17f10b61d456e26', 'signed url');
is($c->signed_url_for($query_test), 'http://example.com/?name=test&crto=b17f10b61d456e26', 'signed url');

done_testing;
__END__
