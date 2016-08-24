package Mojolicious::Plugin::ClosedRedirect;
use Mojo::Base 'Mojolicious::Plugin';
use Mojo::ByteStream 'b';
use Mojo::Util qw/secure_compare url_unescape/;

our $VERSION = '0.07';

# TODO: Prevent Log Injection Attack
#       https://www.owasp.org/index.php/Log_Injection
# TODO: Use rolling private secrets
# TODO: Make this part of the validation framework
# TODO: Support domain whitelisting, like
#       https://github.com/sdsdkkk/safe_redirect
# TODO: Possibly overwrite redirect_to (or not)

# TODO: Test with multiple parameters and multiple array parameters!
# TODO: Accept same origin URLs.
# TODO: Add 'is_local_url' validator check.
#       see http://www.asp.net/mvc/overview/security/preventing-open-redirection-attacks
# TODO: Probably enforce full URLs to handle things like:
#       back_url.starts_with?(root_url)
#       https://www.redmine.org/issues/19577

# Register plugin
sub register {
  my ($plugin, $app, $param) = @_;

  $param ||= {};

  # Load parameter from Config file
  if (my $config_param = $app->config('ClosedRedirect')) {
    $param = { %$param, %$config_param };
  };

  my $p_secret = $param->{secret};

  # Get p_secret or the first application secret
  my $secret = $p_secret || $app->secrets->[0];

  # Establish 'signed_url_for' helper
  $app->helper(
    signed_url_for => sub {
      my $c = shift;

      my $url = $c->url_for(@_);

      # Delete possible 'crto' parameter
      $url->query->remove('crto');

      # Canonicalize
      $url->path->canonicalize;

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

  # Add validation check
  # Alternatively make this a filter instead
  $app->validator->add_check(
    closed_redirect => sub {
      my ($v, $name, $return_url, $method) = @_;
      $method //= '';

      # No URL given
      return 'Redirect URL missing' unless $return_url;

      # No array allowed
      return 'Only one redirect URL allowed' if ref $v->output->{$name} eq 'ARRAY';

      # Check for local url
      if ($method ne 'signed') {
        return if local_url($return_url);
      };

      # Get url
      my $url = Mojo::URL->new($return_url);
      my $url_check;

      # local_url not valid
      # Support signing
      unless ($method eq 'local') {

        # Get 'crto' parameter
        my $check = $url->query->param('crto');

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

            # Check if signed url is valid
            if (secure_compare($url_check, $check)) {

              # TODO: Remove authorization stuff!

              # Rewrite parameter
              $v->output->{$name} = $url->to_string;
              return;
            };
          };
        };
      };

      # Get string
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

      return 'Redirect URL is invalid';
    }
  );
};


# Check for local URL
# Based on http://www.asp.net/mvc/overview/security/preventing-open-redirection-attacks
sub local_url {
  my $url = $_[0];

  $url = url_unescape $url;

  # Alternatively: if path !~ %r{\A/([^/]|\z)}

  my $first  = substr($url, 0, 1);
  my $second = length($url) > 1 ? substr($url, 1, 1) : '';
  if (
    (
      ($first eq '/') && (
        length($url) == 1 ||
          ($second ne '/' && $second ne '\\')
        )
    ) || (
      length($url) > 1 && $first eq '~' && $second eq '/'
    )
  ) {
    return 1;
  };
  return 0;
};


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
vulnerability by limiting to local URLs and using
L<https://webmasters.googleblog.com/2009/01/open-redirect-urls-is-your-site-being.html|signed URLs>.

B<This is early software and the API and functionality may change in various ways!>
B<Wait until it's published on CPAN before you use it!>

=head1 METHODS

=head2 register

=over 2

=item C<secret>

Set a special secret to be used to sign URLs.
Defaults to the first application secret.

=back

All parameters can be set either on registration or as part
of the configuration file with the key C<ClosedRedirect>
(with the configuration file having the higher precedence).

=head1 HELPERS

=head2 signed_url_for

=head2 closed_redirect_to

Using the validation check is preferred.
The helper may be used in case the redirect URL comes from other sources,
like the C<Referrer> header.

=head1 CHECKS

=head2 closed_redirect

  get '/login' => sub {
    my $c = shift;
    my $v = $c->validation;

    # Check for a redirection parameter
    $v->required('return_to')->closed_redirect;

    # Redirect to home page
    return $c->redirect_to('/') if $v->has_error;

    # Redirect to redirection URL
    return $c->redirect_to($v->param('return_to'));
  };

If no parameter is passed, local paths or signed URLs are accepted.
If the parameter C<signed> is passed, only signed URLs are accepted.
If the parameter C<local> is passed, only local URLs are accepted.

If the parameter was signed, the signature will be removed on success.

=head1 HOOKS

=head2 on_open_redirect_attack

  $app->hook(on_open_redirect_attack => sub {
    my ($c, $url) = @_;
    ...
  });

Emitted when an open redirect attack was detected.
Passes the controller object and the URL tried to redirect to.


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
