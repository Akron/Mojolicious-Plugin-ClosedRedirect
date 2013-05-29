package Mojolicious::Plugin::ClosedRedirect;
use Mojo::Base 'Mojolicious::Plugin';
use Mojo::ByteStream 'b';


our $VERSION = 0.01;

our $ERROR = 'An Open Redirect attack was detected';

# Register plugin
sub register {
  my ($plugin, $mojo, $param) = @_;

  my $token_length = $param->{token_length} || 16;
  my $secret = $param->{secret} || $mojo->secret;

  # Establish 'signed_url_for' helper
  $mojo->helper(
    signed_url_for => sub {
      my $c = shift;

      # Get url object
      my $url = $c->url_for(@_);

      # Delete possible parameter
      $url->query->remove('crto');

      # Calculate check
      my $url_check =
	b($url->to_string)->
	  url_unescape->
	    hmac_sha1_sum( 'crto' . $secret );

      # Append check parameter to url
      $url->query({ crto => substr($url_check, 0, $token_length) });
      return $url->to_string;
    });


  # Establish 'closed_redirect_to' helper
  $mojo->helper(
    closed_redirect_to => sub {
      my $c = shift;

      $mojo->log->debug('Check if redirect url is close');

      # Get url
      my $url = $c->url_for( $c->param( shift ) );

      # Get 'crto' parameter
      my $check = $url->query->param('crto');

      # No check parameter available
      if ($check) {

	# Remove parameter
	$url->query->remove('crto');

	# Calculate check
	my $url_check =
	  b($url->to_string)->
	    url_unescape->
	      hmac_sha1_sum( 'crto' . $secret);

	# Check if url is valid
	if (substr($url_check, 0, $token_length) eq $check) {

	  $mojo->log->debug('Check if redirect url is close: It\'s fine');

	  return $c->redirect_to( $url );
	};
      };

      $mojo->log->debug('Check if redirect url is close: It failed');

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

=head1 HELPERS

#   Protection for open redirect_to


  $app->routes->route('/mypath')->name('mypath');

  $c->url_for('acct_login')->query([ return_url => $c->signed_url_for('mytest') ]);



  # Redirect to valid url from $c->param('return_url')
  return if $c->closed_redirect_to('return_url');

  # Fails
  return $c->redirect_to('home');
