package Mojolicious::Plugin::ClosedRedirect;
use Mojo::Base 'Mojolicious::Plugin';
use Mojo::ByteStream 'b';

our $VERSION = 0.03;

our $ERROR = 'An Open Redirect attack was detected';

# Make this part of the validation framework

# Register plugin
sub register {
  my ($plugin, $mojo, $param) = @_;

  my $token_length = $param->{token_length} || 16;
  my $secret = $param->{secret} || $mojo->secrets->[0];

  # Establish 'signed_url_for' helper
  $mojo->helper(
    signed_url_for => sub {
      my $c = shift;

      # Get url object
      my $url = $c->url_for(@_);

      # Delete possible 'crto' parameter
      $url->query->remove('crto');

      # Calculate check
      my $url_check =
	b($url->to_string)->
	  url_unescape->
	    hmac_sha1_sum( 'crto' . $secret );

      $mojo->log->debug(
	'ClosedRedirect: Generate ' . $url_check . ' for ' . $url->to_string
      );

      # Append check parameter to url
      $url->query({ crto => substr($url_check, 0, $token_length) });
      return $url->to_string;
    });


  # Establish 'closed_redirect_to' helper
  $mojo->helper(
    closed_redirect_to => sub {
      my $c = shift;


      $mojo->log->debug("ClosedRedirect: Test1 " . $_[0]);

      # Get url
      my $url = $c->url_for( $c->param( shift ) );

      $mojo->log->debug("ClosedRedirect: Test2 " . $url);

      # Get 'crto' parameter
      my $check = $url->query->param('crto');

      $mojo->log->debug("ClosedRedirect: Test with crto " . ($check || ''));

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

	  $mojo->log->debug('ClosedRedirect: Fine');

	  return $c->redirect_to( $url );
	};
      };

      $mojo->log->debug(
	'ClosedRedirect: Fail. ' .
	'URL is ' . $url->to_string . ' ' .
	'with check ' . ($url_check || '[]')
      );

      # Delete location header
      $c->res->headers->remove('Location');

      # Add error message
      $c->flash(alert => $ERROR);

      return;
    }
  );
};


1;


__END__


=pod

=NAME

Mojolicious::Plugin::ClosedRedirect - Defend Open Redirect Attacks

This plugin helps you to protect your users to not tap into a
L<http://cwe.mitre.org/data/definitions/601.html|OpenRedirect>
vulnerability by using signed URLs.


=head1 METHODS

=head2 register

...

=head1 HELPERS

it is not possible to change session information after a successfull redirect,
so the normal way to deal with that is to have a fallback for non valid
closed redirects in a controller.

  # Check for Open Redirect Attack
  return if $c->closed_redirect_to('return_url');

  # Open Redirect attack discovered
  return $c->redirect_to('home');


  # Protection for open redirect_to


  $app->routes->route('/mypath')->name('mypath');

  $c->url_for('acct_login')->query([ return_url => $c->signed_url_for('mytest') ]);



  # Redirect to valid url from $c->param('return_url')
  return if $c->closed_redirect_to('return_url');

  # Fails
  return $c->redirect_to('home');

=cut
