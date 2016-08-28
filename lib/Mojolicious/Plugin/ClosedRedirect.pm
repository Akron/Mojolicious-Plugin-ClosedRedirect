package Mojolicious::Plugin::ClosedRedirect;
use Mojo::Base 'Mojolicious::Plugin';
use Mojo::ByteStream 'b';
use Mojo::Util qw/secure_compare url_unescape quote/;

our $VERSION = '0.08';

# TODO: Use rolling plugin secrets
# TODO: Support domain whitelisting, like
#       https://github.com/sdsdkkk/safe_redirect
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

  # Establish 'signed_url_for' helper
  # TODO: Better sign_redirect_for
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


  # Add validation check
  # Alternatively make this a filter instead
  $app->validator->add_check(
    closed_redirect => sub {
      my ($v, $name, $return_url, $method) = @_;
      $method //= '';

      # No URL given
      # This is not judged as an Open Redirect attack
      return 'Redirect is missing' unless $return_url;

      my ($err, $url);

      # No array allowed
      if (ref $v->output->{$name} eq 'ARRAY') {
        $err = 'Redirect is defined multiple times';
      }

      # Parameter is fine
      else {

        # Check for local paths
        if ($method ne 'signed') {

          # That's fine
          if (local_path($return_url)) {
            # Get url
            $url = Mojo::URL->new($return_url);

            # Remove parameter if existent
            $url->query->remove('crto');

            # Rewrite parameter
            $v->output->{$name} = $url->to_string;

            return;
          };
        };

        # Get url
        $url = Mojo::URL->new($return_url);

        # local_path not valid
        # Support signing
        unless ($method eq 'local') {

          # Get 'crto' parameter
          my $check = $url->query->param('crto');

          # No check parameter available
          if ($check) {

            # Remove parameter
            $url->query->remove('crto');

            my $url_check;

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
      };

      $err //= 'Redirect is invalid';

      # Emit hook
      $app->plugins->emit_hook(
        on_open_redirect_attack => ( $name, $return_url, $err )
      );

      # Warn in log
      # Prevents log-injection attack
      $app->log->warn(
        "Open Redirect Attack - $err: URL for " . quote($name) . ' is ' . quote($return_url)
        );

      return $err;
    }
  );
};


# Check for local Path
# Based on http://www.asp.net/mvc/overview/security/preventing-open-redirection-attacks
sub local_path {
  my $url = $_[0];

  $url = url_unescape $url;

  return 1 if $url =~ m!^(?:/(?:[^\/\\]|$)|~\/.)!;
  return;
};


1;


__END__

=pod

=head1 NAME

Mojolicious::Plugin::ClosedRedirect - Defend Open Redirect Attacks


=head1 SYNOPSIS

  plugin 'ClosedRedirect';

  get '/login' => sub {
    my $c = shift;
    my $v = $c->validation;

    # Check for a redirection parameter
    $v->required('fwd')->closed_redirect;

    # Redirect to redirection URL
    return $c->redirect_to($v->param('fwd')) unless $v->has_error;

    # Redirect to home page on error
    return $c->redirect_to('/');
  };


=head1 DESCRIPTION

This plugin helps you to avoid
L<http://cwe.mitre.org/data/definitions/601.html|OpenRedirect>
vulnerabilities in your application by limiting redirections
to either local paths or
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

  $c->url_for('/login')->query([
    fwd => $c->signed_url_for('http://example.com/path')
  ]);

Sign a redirection URL with the defined secret.

=head1 CHECKS

=head2 closed_redirect

  # Check for a redirection parameter
  $c->validation->required('fwd')->closed_redirect;

Check the parameter in scope for being a valid URL to redirect to.

If no parameter is passed to the check, local paths or signed URLs are accepted.
If the parameter C<signed> is passed, only signed URLs are accepted.
If the parameter C<local> is passed, only local paths are accepted.

If the parameter was signed, the signature with the URI parameter C<crto>
will be removed on success (even if the URL was local).

=head1 HOOKS

=head2 on_open_redirect_attack

  $app->hook(on_open_redirect_attack => sub {
    my ($name, $url, $msg) = @_;
    ...
  });

Emitted when an open redirect attack was detected.
Passes the parameter name, the first failing URL,
and the error message of the check.


=head1 BUGS and CAVEATS

The URLs are currently signed using HMAC-SHA-1 and a secret.
There are known attacks to SHA-1.

Local redirects need to be paths -
URLs with host information are not supported.


=head1 AVAILABILITY

  https://github.com/Akron/Mojolicious-Plugin-ClosedRedirect


=head1 COPYRIGHT AND LICENSE

Copyright (C) 2016, L<Nils Diewald|http://nils-diewald.de/>.

This program is free software, you can redistribute it
and/or modify it under the terms of the Artistic License version 2.0.

=cut
