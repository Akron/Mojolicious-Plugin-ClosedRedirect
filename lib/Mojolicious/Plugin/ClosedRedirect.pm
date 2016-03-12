package Mojolicious::Plugin::ClosedRedirect;
use Mojo::Base 'Mojolicious::Plugin';
use Mojo::ByteStream 'b';

our $VERSION = '0.05';

# TODO: Make this part of the validation framework
# TODO: Check for all secrets in the roll!
# Do not modify the sha1-token!

# Register plugin
sub register {
  my ($plugin, $app, $param) = @_;

  $param ||= {};

  # Load parameter from Config file
  if (my $config_param = $app->config('ClosedRedirect')) {
    $param = { %$param, %$config_param };
  };

  # Should the user be alerted of
  # ClosedRedirect attacks?
  my $silent = !!($param->{silent});
  unless ($silent) {
    # Add internationalization
    $app->plugin(Localize => {
      dict => {
	ClosedRedirect => {
	  error => {
	    _ => sub { $_->locale },
	    -en => 'An Open Redirect attack was detected',
	    de => 'Ein Open Redirect Angriff wurde festgestellt'
	  }
	}
      }
    });

    # Load notifications plugin
    unless (exists $app->renderer->helpers->{notify}) {
      $app->plugin('Notifications');
    };
  };

  my $token_length = $param->{token_length} || 16;
  my $secret = $param->{secret} || $app->secrets->[0];


  # Create a sign closure
  my $_sign = sub {
    my $url = shift;

    # Delete possible 'crto' parameter
    $url->query->remove('crto');

    # Canonicalize
    $url->path->canonicalize;

    # Calculate check
    my $url_check =
      b($url->to_string)
	->url_unescape
	  ->hmac_sha1_sum( 'crto' . $secret );

    # Append check parameter to url
    $url->query({ crto => substr($url_check, 0, $token_length) });
    return $url->to_string;
  };


  # Establish 'signed_url_for' helper
  $app->helper(
    signed_url_for => sub {
      my $c = shift;

      # Get url object
      return $_sign->($c->url_for(@_));
    });


  # Establish 'closed_redirect_to' helper
  $app->helper(
    closed_redirect_to => sub {
      my $c = shift;

      # Return false in case no return_url parameter was set
      my $return_url = $c->param( shift ) or return;

      # Get url
      my $url = $c->url_for($return_url);

      # Get 'crto' parameter
      my $check = $url->query->param('crto');

      my $url_check;

      # No check parameter available
      if ($check) {

	# Remove parameter
	$url->query->remove('crto');

	# Calculate check
	$url_check =
	  b($url->to_string)->
	    url_unescape->
	      hmac_sha1_sum( 'crto' . $secret);

	# Check if url is valid
	if (substr($url_check, 0, $token_length) eq $check) {
	  return $c->redirect_to( $url );
	};
      };

      # TODO: report in attack log!
      $app->log->warn(
	'Open Redirect Attack: ' .
	  'URL is ' . $url->to_string . ' with ' . ($url_check || 'no check')
	);

      # Delete location header
      $c->res->headers->remove('Location');

      # Add error message
      unless ($silent) {
	$c->notify(error => $c->loc('ClosedRedirect_error'));
      };

      return;
    }
  );
};


1;


__END__

=pod

=head1 NAME

Mojolicious::Plugin::ClosedRedirect - Defend Open Redirect Attacks

=head1 SYNOPSIS

  # Check for Open Redirect Attack
  return if $c->closed_redirect_to('return_url');

  # Open Redirect attack discovered
  return $c->redirect_to('home');

  # Protection for open redirect_to

  $app->routes->route('/mypath')->name('mypath');

  $c->url_for('acct_login')->query([
    return_url => $c->signed_url_for('mytest')
  ]);

  # Redirect to valid url from $c->param('return_url')
  return if $c->closed_redirect_to('return_url');

  # Fails
  return $c->redirect_to('home');


=head1 DESCRIPTION

This plugin helps you to protect your users not to tap into a
L<http://cwe.mitre.org/data/definitions/601.html|OpenRedirect>
vulnerabilities by using signed URLs.

=head1 METHODS

=head2 register

=over 2

=item C<silent>

Accepts a boolean value, if users should not receive a notification
on redirect attacs. Defaults to not being silent.

=item C<token_length>

Set the length of the secret token to append to redirect locations.
Defaults to C<16>.

=item C<secret>

Pass the secret to be used to hash on redirect locations.
Defaults to the first application secret.

=back

All parameters can be set either on registration or as part
of the configuration file with the key C<ClosedRedirect>
(with the configuration file having the higher precedence).

=head1 HELPERS

=head1 BUGS and CAVEATS

The URLs are currently signed using SHA-1 and a free, prefixed secret
(with the default being the application secret).
There are known attacks to SHA-1, so this solution does not mean
you should not validate the URL further.

It is not possible to change session information after a successfull redirect,
so the normal way to deal with that is to have a fallback for non valid
closed redirects in a controller.

=head1 AVAILABILITY

  https://github.com/Akron/Mojolicious-Plugin-ClosedRedirect

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2016, L<Nils Diewald|http://nils-diewald.de/>.

This program is free software, you can redistribute it
and/or modify it under the terms of the Artistic License version 2.0.

=cut
