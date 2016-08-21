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
my $attack = 0;
my $url;

$app->hook(
  on_open_redirect_attack => sub {
    (my $c, $url) = @_;
    $attack = 1;
  }
);

my $pure = '/mypath';
my $fine = $pure . '?crto=a4538583e3c0a534f3863050804c746a9bd92a2f';
is($app->signed_url_for('myname'), $fine, 'signed url');
is($c->signed_url_for('myname'), $fine, 'signed url');
ok(!$attack, 'No attack');

# Set correct
ok($c->param(return_url => $fine), 'Set parameter');
ok($c->closed_redirect_to('return_url'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');
ok(!$attack, 'No attack');

# Set false
ok($c->param(return_url => substr($fine, 1)), 'Set parameter');
ok(!$c->closed_redirect_to('return_url'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');
ok($attack, 'Attack!');
like($url, qr/mypath/, 'Problem');
$attack = 0;
$url = undef;

# Set false
ok($c->param(return_url => substr($fine, 0, -1)), 'Set parameter');
ok(!$c->closed_redirect_to('return_url'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');
ok($attack, 'Attack!');
is($url, '/mypath', 'Problem');
$attack = 0;

# Set correct
ok($c->param(return_url => $fine), 'Set parameter');
ok($c->closed_redirect_to('return_url'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');
ok(!$attack, 'Attack!');

# ---

$pure = '/my/peter/path';
$fine = $pure . '?crto=e10b3e94fbf66c38444ade5dde9447ae369d9baf';

is($app->signed_url_for('myname2', second => 'peter'), $fine, 'signed url');
is($c->signed_url_for('myname2', second => 'peter'), $fine, 'signed url');

# Set correct
ok($c->param(return_url_2 => $fine), 'Set parameter');
ok($c->closed_redirect_to('return_url_2'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');
ok(!$attack, 'Attack!');

# Set false
ok($c->param(return_url_2 => substr($fine, 1)), 'Set parameter');
ok(!$c->closed_redirect_to('return_url_2'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');
ok($attack, 'Attack!');
$attack = 0;

# Set false
ok($c->param(return_url_2 => substr($fine, 0, -1)), 'Set parameter');
ok(!$c->closed_redirect_to('return_url_2'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');
# is($c->flash('alert'), 'An Open Redirect attack was detected', 'Flash alert');
ok($attack, 'Attack!');
$attack = 0;


# Set correct
ok($c->param(return_url_2 => $fine), 'Set parameter');
ok($c->closed_redirect_to('return_url_2'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');
ok(!$attack, 'No attack');

# ---


$pure = '/mypath?test=hmm';
$fine = $pure . '&crto=3da434e37b38bef41132aacf82d5b91c7cedbbc4';

is($app->signed_url_for($app->url_for('myname')->query({ test => 'hmm' })), $fine, 'signed url');
is($c->signed_url_for($c->url_for('myname')->query({ test => 'hmm' })), $fine, 'signed url');

# Set correct
ok($c->param(redirect_to => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');
ok(!$attack, 'No attack');

# Set false
ok($c->param(redirect_to => substr($fine, 1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');
ok($attack, 'Attack!');
$attack = 0;

# Set false
ok($c->param(redirect_to => substr($fine, 0, -1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');
ok($attack, 'Attack!');
$attack = 0;

# Set correct
ok($c->param(redirect_to => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');
ok(!$attack, 'No attack');

# ---


$pure = 'http://example.com/';
$fine = $pure . '?crto=87760c7ca623ce8083bfb7b93ffd78ad88611b07';
is($app->signed_url_for('http://example.com/'), $fine, 'signed url');
is($c->signed_url_for('http://example.com/'), $fine, 'signed url');

# Set correct
ok($c->param(redirect_to_2 => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to_2'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');
ok(!$attack, 'No attack');

# Set false
ok($c->param(redirect_to_2 => substr($fine, 1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to_2'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');
ok($attack, 'Attack!');
$attack = 0;

# Set false
ok($c->param(redirect_to_2 => substr($fine, 0, -1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to_2'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');
ok($attack, 'Attack!');
$attack = 0;

# Set correct
ok($c->param(redirect_to_2 => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to_2'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');
ok(!$attack, 'No attack');

# ---

$pure = 'http://example.com/?name=test#age';
$fine = 'http://example.com/?name=test&crto=8a986b12b3d7c6ae668238d41ec08907076d4d04#age';
is($app->signed_url_for($pure), $fine, 'signed url');
is($c->signed_url_for($pure), $fine, 'signed url');

# Set correct
ok($c->param(redirect_to_3 => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to_3'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');
ok(!$attack, 'No attack');

# Set false
ok($c->param(redirect_to_3 => substr($fine, 1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to_3'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');
ok($attack, 'Attack!');
$attack = 0;

# Set false
ok($c->param(redirect_to_3 => substr($fine, 0, -1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to_3'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');
ok($attack, 'Attack!');
$attack = 0;

# Set correct
ok($c->param(redirect_to_3 => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to_3'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');
ok(!$attack, 'No attack');


# ---


my $base = 'http://example.com/?name=test&crto=8a986b12b3d7c6ae668238d41ec08907076d4d04#age';
$pure = 'http://example.com/?name=test#age';
$fine = 'http://example.com/?name=test&crto=8a986b12b3d7c6ae668238d41ec08907076d4d04#age';
is($app->signed_url_for($base), $fine, 'signed url');
is($c->signed_url_for($base), $fine, 'signed url');

# Set correct
ok($c->param(redirect_to_3 => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to_3'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');
ok(!$attack, 'No attack');


# Set false
ok($c->param(redirect_to_3 => substr($fine, 1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to_3'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');
ok($attack, 'Attack!');
$attack = 0;

# Set false
ok($c->param(redirect_to_3 => substr($fine, 0, -1)), 'Set parameter');
ok(!$c->closed_redirect_to('redirect_to_3'), 'Redirect not fine');
ok(!$c->res->headers->location, 'Redirect location is not fine');
ok($attack, 'Attack!');
$attack = 0;

# Set correct
ok($c->param(redirect_to_3 => $fine), 'Set parameter');
ok($c->closed_redirect_to('redirect_to_3'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');
ok(!$attack, 'No attack');


my $query_test = 'http://example.com/?name=test';

is($app->signed_url_for($query_test), 'http://example.com/?name=test&crto=3f603010ed397ddb020a5d42efc3329e4c9f0a62', 'signed url');
is($c->signed_url_for($query_test), 'http://example.com/?name=test&crto=3f603010ed397ddb020a5d42efc3329e4c9f0a62', 'signed url');

done_testing;
__END__
