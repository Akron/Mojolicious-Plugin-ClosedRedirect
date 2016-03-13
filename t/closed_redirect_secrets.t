#!/usr/bin/env perl
use Mojolicious::Lite;
use Test::Mojo;
use Test::More;

app->secrets(['123']);

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

my $pure = $c->url_for('myname');
my $signed = $app->signed_url_for('myname');
like($signed, qr/crto/, 'Signed');
like($signed, qr!mypath!, 'Signed');

ok($c->param(return_url => $signed), 'Set parameter');
ok($c->closed_redirect_to('return_url'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');

# Rolling secrets!
app->secrets(['456', '123']);

ok($c->closed_redirect_to('return_url'), 'Redirect fine');
is($c->res->headers->location, $pure, 'Redirect location is fine');

done_testing;
__END__
