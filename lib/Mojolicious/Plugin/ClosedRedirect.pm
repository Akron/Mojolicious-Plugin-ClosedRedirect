package Mojolicious::Plugin::ClosedRedirect;
use Mojo::Base 'Mojolicious::Plugin';
use Mojo::ByteStream 'b';
use Mojo::Util qw/secure_compare/;

our $VERSION = '0.07';

# TODO: Prevent Log Injection Attack
#       https://www.owasp.org/index.php/Log_Injection
# TODO: Make this part of the validation framework
# TODO: Support domain whitelisting, like
#       https://github.com/sdsdkkk/safe_redirect
# TODO: Possibly overwrite redirect_to (or not)

# TODO: Test with multiple parameters and multiple array parameters!
# TODO: Accept same origin URLs.
# TODO: Add 'is_local_url' validator check.
#       see http://www.asp.net/mvc/overview/security/preventing-open-redirection-attacks

# Register plugin
sub register {
  my ($plugin, $app, $param) = @_;

  $param ||= {};

  # Load parameter from Config file
  if (my $config_param = $app->config('ClosedRedirect')) {
    $param = { %$param, %$config_param };
  };

  my $p_secret = $param->{secret};

  # Establish 'signed_url_for' helper
  $app->helper(
    signed_url_for => sub {
      my $c = shift;

      my $url = $c->url_for(@_);

      # Delete possible 'crto' parameter
      $url->query->remove('crto');

      # Canonicalize
      $url->path->canonicalize;

      # Get p_secret or the first application secret
      my $secret = $p_secret || $app->secrets->[0];

      # Calculate check
      my $url_check =
        b($url->to_string)
        ->url_unescape
        ->hmac_sha1_sum($secret);

      # Append check parameter to url
      $url->query({ crto => $url_check });
      return $url->to_string;
    }
  );


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
        foreach ($p_secret // @{$app->secrets}) {

          # Calculate check
          $url_check =
            b($url->to_string)->
            url_unescape->
            hmac_sha1_sum($_);

          # Check if url is valid
          if (secure_compare($url_check, $check)) {
            return $c->redirect_to( $url );
          };
        };
      };

      my $url_string = $url->to_string;

      # Emit hook
      $app->plugins->emit_hook(
        on_open_redirect_attack => ( $c, $url_string )
      );

      # Warn in log
      $app->log->warn(
        'Open Redirect Attack: ' .
          "URL is $url_string with " . ($url_check || 'no check')
        );

      # Delete location header
      $c->res->headers->remove('Location');

      return;
    }
  );

  $app->validator->add_check(
    closed_redirect => sub {
      my ($v, $name, $return_url, @arguments) = @_;

      # No URL given
      return 1 unless $return_url;

      # TODO: Prevent for:
      # http://example.com/view_topic?view=//www.qualys.com
      # return if is_local_url();

      # Get url
      my $url = $app->url_for($return_url);

      # TODO: is_local

      # Get 'crto' parameter
      my $check = $url->query->param('crto');

      my $url_check;

      # No check parameter available
      if ($check) {

        # Remove parameter
        $url->query->remove('crto');

        # Check all secrets
        foreach ($p_secret || @{$app->secrets}) {

          # Calculate check
          $url_check =
            b($url->to_string)->
            url_unescape->
            hmac_sha1_sum($_);

          # Check if url is valid
          return if secure_compare($url_check, $check);
        };
      };

      my $url_string = $url->to_string;

      # Emit hook
      $app->plugins->emit_hook(
        on_open_redirect_attack => ( $url_string )
      );

      # Warn in log
      $app->log->warn(
        'Open Redirect Attack: ' .
          "URL is $url_string with " . ($url_check || 'no check')
        );

      return 1;
    }
  );
};


# Todo
# sub is_local_url;
# sub is_signed_url;


1;


__END__

=pod

=head1 NAME

Mojolicious::Plugin::ClosedRedirect - Defend Open Redirect Attacks

=head1 SYNOPSIS

  plugin 'ClosedRedirect';

  # Check for an Open Redirect Attack
  return if $c->closed_redirect_to('return_url');

  # Open Redirect attack discovered
  return $c->redirect_to('home');

  # Protect URLs for open redirect attacks
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
vulnerability by using signed URLs.

B<This is early software and the API and functionality may change in various ways!>
B<Wait until it's published on CPAN before you use it!>

=head1 METHODS

=head2 register

=over 2

=item C<secret>

Pass a secret to be used to hash on redirect locations.
Defaults to the first application secret, which is also
recommended.

=back

All parameters can be set either on registration or as part
of the configuration file with the key C<ClosedRedirect>
(with the configuration file having the higher precedence).

=head1 HELPERS

=head2 signed_url_for

=head2 closed_redirect_to

=head1 HOOKS

=head2 on_open_redirect_attack

  $app->hook(on_open_redirect_attack => sub {
    my ($c, $url) = @_;
    ...
  });

Emitted when an open redirect attack was detected.
Passes the controller object and the URL to redirect to.


=head1 BUGS and CAVEATS

The URLs are currently signed using SHA-1 and secret
(with the default being the application secret).
There are known attacks to SHA-1, so this solution does not mean
you should not validate the URL further in critical scenarios.

It is not possible to change session information after a successful redirect,
so the normal way to deal with that is to have a fallback for non valid
closed redirects in a controller.


=head1 AVAILABILITY

  https://github.com/Akron/Mojolicious-Plugin-ClosedRedirect


=head1 COPYRIGHT AND LICENSE

Copyright (C) 2016, L<Nils Diewald|http://nils-diewald.de/>.

This program is free software, you can redistribute it
and/or modify it under the terms of the Artistic License version 2.0.

=cut
