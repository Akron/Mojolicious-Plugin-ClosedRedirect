#!/usr/bin/env perl
use Mojolicious::Lite;
use Test::Mojo;
use Test::More;
use Mojo::Util qw/url_escape/;
use Test::Memory::Cycle;

app->secrets(['123']);

plugin 'ClosedRedirect';

# Check for signed redirect parameter
get '/signed' => sub {
  my $c = shift;
  my $v = $c->validation;

  $v->required('fwd')->closed_redirect('signed');

  return $c->redirect_to($v->param('fwd')) unless $v->has_error;

  my $fail = $v->param('fwd') // 'no';
  $fail .= '-' . join(',', @{$v->error('fwd')});
  return $c->render(text => 'fail-' . $fail, status => 403);
} => 'signed';


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
my $signed = $app->close_redirect_to('myname');
like($signed, qr/crto/, 'Signed');
like($signed, qr!mypath!, 'Signed');

$t->get_ok('/signed?fwd=' . url_escape($signed))
  ->status_is(302)
  ->header_is('Location', $pure);

# Rolling secrets!
app->secrets(['456', '123']);

# Reload plugin so secrets are in effect
plugin 'ClosedRedirect';

my $signed2 = $app->close_redirect_to('myname');
isnt($signed, $signed2, 'Secrets differ');

$t->get_ok('/signed?fwd=' . url_escape($signed))
  ->status_is(302)
  ->header_is('Location', $pure);

$t->get_ok('/signed?fwd=' . url_escape($signed2))
  ->status_is(302)
  ->header_is('Location', $pure);

{
  local $SIG{__WARN__} = sub { };
  memory_cycle_ok(app);
};

done_testing;
__END__
