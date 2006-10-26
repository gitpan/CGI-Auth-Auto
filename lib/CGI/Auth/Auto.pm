package CGI::Auth::Auto;
use CGI;
use CGI::Carp;
use strict;
use base qw(CGI::Auth);
#TODO: make this do a cgi::session also!
our $VERSION = sprintf "%d.%03d", q$Revision: 1.4 $ =~ /(\d+)/g;

# it's a bitch to pass new param to new - this module CGI::Auth sucks ass to inherit


# override check so that we can do cookie thing
sub check {
	my $self = shift;	
	$self->_pre_check;
	$self->SUPER::check; # access overridden method
	$self->_post_check;
}



# this runs before auth check
sub _pre_check {
	my $self = shift;
	$self->_requested_logout or	
		# attempt to get cookie value into cgi param	so auth check can read session id thingie
		
		$self->{cgi}->param( -name=>$self->sfparam_name, -value=> $self->{cgi}->cookie($self->sfparam_name) );
	return 1;
}

sub set_cookie_expire_time {
	my $self= shift;
	my $val = shift; $val or croak("must have valid arg to set_cookie_expire()");
	$self->{cookie_expire_time}= $val;
	return $self->{cookie_expire_time};
}

sub get_cookie_expire_time {
	my $self= shift;
	$self->{cookie_expire_time} ||= '+1h';
	return $self->{cookie_expire_time};
}

sub get_logout_param_name {
	my $self = shift;
	$self->{logout_param_name} ||= 'logout';
	return $self->{logout_param_name};
}
sub set_logout_param_name {
	my $self = shift;
	my $val = shift; $val or croak("must have arg to set_logout_param_name()");
	$self->{logout_param_name} = $val;
	return $self->{logout_param_name};
}





# this will only run if an auth check is successful, so sfparam_value WILL be there
sub _post_check {
	my $self = shift;
	if ($self->{cgi}->cookie($self->sfparam_name)){ return 1; } # already set.
		
	# at this poinnt cookie is NOT set, and sfparam_value IS available,
	# otherwise code would not get to this point

		
	print $self->{cgi}->redirect(
		-uri => $self->{formaction}, 
		-cookie=> $self->{cgi}->cookie(
			-name=>$self->sfparam_name, 
			-value=>$self->sfparam_value, 
			-expire=> $self->get_cookie_expire_time)
		);

	return 1;
}

sub _requested_logout {
	my $self= shift;
	defined $self->{cgi}->param($self->get_logout_param_name) or return 0;	
	$self->logout;
}


sub logout {
	my $self = shift;
	
	if ( $self->{cgi}->cookie($self->sfparam_name)) { $self->endsession; }
	
	print $self->{cgi}->redirect(
		-uri => $self->{formaction}, 
		-cookie=> $self->{cgi}->cookie(
			-name=>$self->sfparam_name, 
			-value=>'', 
			-expire=>'now')
		);
	exit;
}


# legacy
sub run {
	my $self = shift;
	$self->check;
}

sub get_cgi {
	my $self = shift;
	return $self->{cgi};
}

1;

__END__

=head1 NAME

CGI::Auth::Auto

=head1 SYNOPSIS

my $auth = new CGI::Auth::Auto(...); # see CGI::Auth
$auth->check;

=head1 DESCRIPTION

Adds auto session id passing mechanism to CGI::Auth. Also provides simple auth drop system (logout).

This module inherits CGI::Auth.

CGI::Auth is great. It's simple to use. You can hide scripts behind authorization with
a simple prepend to code. I love it.
Thing is.. It still leaves us to pass around the sfparam_value around, so that 
CGI::Auth can check the session validity each time.

This module adds functionality to check() to maintain a cookie for you.
It also provides for a logout medthod- to get rid of it.

You use this exactly as you would use CGI::Auth, only the client *must* accept cookies.
And you no longer have to worry about passing the session id returned from CGI::Auth.
Basically this is like a plugin for any script you have that adds a nice authorization.

Keep in mind you can fully edit the template for the login to make it look like whatever 
you want.

=head1 EXAMPLE

Example assumes you installed CGI::Auth and its support files.

	#!/usr/bin/perl -w
	use strict;
	use CGI::Auth::Auto;
	my $auth = new CGI::Auth::Auto({
	   -formaction   => '/home/myself/cgi-bin/this_script.cgi',
		-authdir      => '/home/myself/cgi-bin/auth', # see CGI::Auth
		-authfields   => [
		        {id => 'user', display => 'User Name', hidden => 0, required => 1},
		        {id => 'pw', display => 'Password', hidden => 1, required => 1},
		    ],
	});

	$auth->check;

	print "Content-type: text/html\n\n";
	print "<h1>Step 1</h1><p>Ok you're in. You can double check that the cookie worked by refreshing this page.</p>";
	print "<p>If you are not prompted for login again, it worked.</p>";
	print "<h1>Step 2</h1><p>Next thing you can try is logging out: <a href=\"/cgi-bin/this_script.cgi?logout=1\">[logout]</a></p>");

	exit;


=head1 DETAILS

It adds extra functionality to CGI::Auth::check to try to retrieve cookie from client,
it makes a cookie if it should.

You must read documentation for CGI::Auth for arguments to object constructor, template
customization, and usage.

=cut



=head1 METHODS


=head2 set_cookie_expire_time()

Default is +1h 
You can set the cookie expire time before check is called to change this value.

	my $auth = new CGI::Auth( ... );	
	$auth->set_cookie_expire_time('+15m');
	$auth->check;

If a cookie is made because user logged in, then it will be set to 15 minutes expiry
instead of the default 1 hour.


=head2 get_cookie_expiry()

If you want to know what the expiry was set at. I don't know why you may want this, but
it keeps people from having to check the internals. Returns '+1h' by default. If you 
have used set_cookie_expire() then it would return that value.


=head2 set_logout_param_name() and get_logout_param_name()

By default the logout field cgi parameter name is 'logout'. You can change the name this way:

	my $auth = new CGI::Auth( ... );	
	$auth->set_logout_param_name('elvis_has_left_the_building');
	$auth->check;

That means that http://mysite.com/cgi-bin/myapp.cgi?logout=1 will no longer log an authorized 
user out. But http://mysite.com/cgi-bin/myapp.cgi?elvis_has_left_the_building=1 will work 
instead.


=head2 logout()

Forces logout. Makes cookie expired and blank.
Then redirects to whatever CGI::Auth formaction was set to.
Then exits.



=head2 get_cgi()

Returns cgi object used, for re-use.

	my $cgi = $auth->get_cgi;



=head1 LOGGING OUT

This module tries to detect a logout request when you call the medhod check().
If there is a field submitted via a form or url query string (POST or GET) that is called
logout and it holds a true value, it will call method logout().
If the url reads http://mysite.com/cgi-bin/myapp.cgi?logout=1 
Then you will be.. logged out.

=head2 logout() EXAMPLE

Method logout() forces logout. This calls CGI::Auth method endsession() (see CGI::Auth doc), this sets the 
cookie expiry to 'now', and clears the CGI::Auth session id value from the cookie.
Effectively logging you out.
Keep in mind that logout() calls a CGI.pm redirect and then exits! 
This is to assure nothing else runs after that.

	if ($mycode_has_decided_to_boot_this_user){
		$auth->logout;
	}	

If the user maybe called an bad instruction or submitted funyn data, or you detect a possible
intrusion etc.. Then your code should log it, and then call logout() as a last step.

	my $auth = new CGI::Auth(...);
	$auth->check;

	# check tainted data
	# ...
	

	if( $oh_no_this_tainted_data_sucks ){

		# ok log it
		# ...
		
		#ok drop this auth and log user out
		$auth->logout;
	}
	
	# nothing wrong.. continue script..
	# ...



=head1 SEE ALSO

CGI::Auth, CGI::Cookie, HTML::Template 

=head1 AUTHOR

Leo Charre leo (at) leocharre (dot) com

=cut
