package CGI::Auth::Auto;
use Carp;
use strict;
use base qw(CGI::Auth);
#use Smart::Comments '###';
our $VERSION = sprintf "%d.%02d", q$Revision: 1.10 $ =~ /(\d+)/g;


sub new {
	my $proto = shift;
   my $class = ref($proto) || $proto;
	my $self = {};
	bless $self, $class;

	my $param = shift;
	$param->{-authfields} ||= [
            {id => 'user', display => 'User Name', hidden => 0, required => 1},
            {id => 'pw', display => 'Password', hidden => 1, required => 1},
        ];
	$param->{-authdir} ||= (defined $ENV{DOCUMENT_ROOT}) ? "$ENV{DOCUMENT_ROOT}/../cgi-bin/auth" : undef;	
	$param->{-formaction} ||= $ENV{SCRIPT_NAME} ? $ENV{SCRIPT_NAME} : undef;

	$self->init($param) or return undef;

	return $self;
}





# override check so that we can do cookie thing
sub check {
	my $self = shift;	
	$self->_pre_check;
	$self->SUPER::check; # access overridden method
	$self->_post_check;
}



# this runs before auth check
# RATIONALE: pre only tries to load an auth string (unless logout is detected)
sub _pre_check {
	my $self = shift;



	# 1) first of all see if a prev sess_file id (filename really) can be gotten from cookie	
	my $sess_file = $self->_get_sess_file_from_cookie 
		or # no sess_file on cooie? no harm done.. just return.
			return; 





	# 2) ok. so the cookie has a sess_file in it...	
	# TODO: had to mess with internals of CGI::Auth ( with $self->{sess_file} ) because that module
	# does not provide for a set() type of method for the sess_file, it does accept as constructor
	# but i'd rather leave the constructor to do what it does, which seems to be to assure that 
	# CGI::Auth finds its support files, user db, template, etc.
	
	$self->{sess_file} = $sess_file; # <- had to mess with CGI::Auth internals here. 
	unless( $self->OpenSessionFile ){ # CGI::Auth::OpenSessionFile() checks with $CGI::Auth::OpenSessionFile::sess_file
		# delete the cookie 
		$self->_ruin_cookie_and_redirect and exit(0);
	}
	
	
	
	
	# 3) cookie was found, sess_file was ok.. now pass it for CGI::Auth::check() to use later.
	### $sess_file
	$self->{cgi}->param( -name=> $self->sfparam_name, -value=> $sess_file );
	
	return 1;
}



sub _ruin_cookie_and_redirect {
	my $self = shift;
	
	print $self->get_cgi->redirect(
		-uri			=> $self->{formaction}, 
		-cookie		=> 
			$self->get_cgi->cookie(
				-name		=> $self->sfparam_name, 
				-value	=> '',
				-expire	=> 'now'
			)
	);

	return 1;
}

sub _set_cookie_and_redirect {
	my $self = shift;
	
	print $self->get_cgi->redirect(
		-uri			=> $self->{formaction}, 
		-cookie		=> 
			$self->get_cgi->cookie(
				-name		=> $self->sfparam_name, 
				-value	=> $self->sfparam_value,
				-expire	=> $self->get_cookie_expire_time
			)
	);

	return 1;
}








# post_check() only runs if user is successfully authenticated.
# its task is 
#	a) to assure a cookie is present.
#  b) check for a logout for this already authenticated user
sub _post_check {
	my $self = shift;

	# 1) assure cookie is here
	unless ( $self->_get_sess_file_from_cookie ) { # if no cookie
		$self->_set_cookie_and_redirect() and exit(0);	
	}

	# 2) detect logout for authenticated user
	# ok. so now we found cookie and sess_file id in it- did the user request a logout???
		
	if ( $self->_requested_logout ) { # check if logout was requested.	
		$self->logout; # logout will exit(0). we dont do it here because logout() method could be called directly.		
	};
	
	return 1;
}






sub logout {
	my $self = shift;

	# delete auth session 
	$self->endsession; 

	# ruin cookie and redirects back here
	$self->_ruin_cookie_and_redirect and exit(0);	
}





# legacy
sub run {
	my $self = shift;
	$self->check;
}







# basic get and set methods. useful..
# these methods dont do anything major like exit or redirect etc

sub get_cgi {
	my $self = shift;
	return $self->{cgi};
}

sub username {
	my $self = shift;
	my $username =	$self->OpenSessionFile;
	$username or return;
	return $username;
}

sub _get_sess_file_from_cookie {
	## _load_cookie()
	my $self = shift;
	my $session_file = $self->get_cgi->cookie($self->sfparam_name);	
	$session_file or return;
	return $session_file;
}

sub _requested_logout {
	my $self= shift;
	defined $self->{cgi}->param($self->get_logout_param_name) or return 0;
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




1;

__END__

=pod

=head1 NAME

CGI::Auth::Auto - Automatic authentication maintenance and persistence for cgi scrips.

=head1 SYNOPSIS

	my $auth = new CGI::Auth::Auto;
	$auth->check;

	# ok, authenticated, logged in.

=head1 DESCRIPTION

CGI::Auth is a nice module- But it leaves you with the responsibility of passing around
the "session id"- Via query string, in a form, a cookie, etc.
It also has no defaults for its constructor parameters.

I wanted to be able to simply drop in a line into any cgi application and have it take 
care of authentication without any further change to the code.
I also wanted to not *have* to pass certain arguments to the constructor. So new() constrcutor
has been overridden to optionally use default params for -authfields -logintmpl -authdir 
and -formaction. 

CGI::Auth::Auto has automatic "sess_file" id passing via a cookie.

This module inherits CGI::Auth.

This module adds functionality to check() to keep track of the sess_file id for you, and to
detect a user "logout" and do something about it.

You use this exactly as you would use CGI::Auth, only the client *must* accept cookies.
And you no longer have to worry about passing the session id returned from CGI::Auth.
Basically this is like a plugin for any script you have that adds a nice authorization.

Keep in mind you can fully edit the template for the login to make it look like whatever 
you want.

=head1 OVERRIDDEN METHODS

=head2 new()

Exactly like CGI::Auth new(). Added functionality has been added.
Now you have the option to not pass any parameters to new().
Default constructor parameters have been placed for the lazy. 

These are the parameters that if left out to new(), will be set to defaults:
-authfields, -authdir, and -formaction.

Thus if you normally CGI::Auth new() like this:

	my $auth = new CGI::Auth({
		-formaction             => $ENV{SCRIPT_NAME},	
		-authfields             => [
            {id => 'user', display => 'User Name', hidden => 0, required => 1},
            {id => 'pw', display => 'Password', hidden => 1, required => 1},
        ],
	   -authdir                => $ENV{DOCUMENT_ROOT}."/../cgi-bin/auth",
	});

You can use this module and do this instead:

	my $auth = new CGI::Auth::Auto;

-formaction 
Atempts to default to $ENV{SCRIPT_NAME}. This is the environment variable on apache
for the calling script. Very useful.
Note that if you did not provided this argument and $ENV{SCRIPT_NAME} is not set, it 
won't work. (You'll know it didn't work.)


-authdir
Now a default value of $ENV{DOCUMENT_ROOT} ../cgi-bin/authdir is present.
That means for most hosting accounts if you have this kind of (very common) setup:
/path/to/home/
           |__ public_html/
           |__ cgi-bin/

You should place the support files that come with CGI::Auth as 
/path/to/home/
           |__ public_html/
           |__ cgi-bin/
                   \__ authdir/
                         |__ authman.pl
                         |__ user.dat
                         |__ login.html
                         |__ sess/
                         |__ AuthCfg.pm

Remember you can still tell new() to use whatever you want for these arguments.
This added functionality simply enables you to instance without any arguments.


=head2 check()

Checks for existing authentication in a cookie.
Prompts for authentication (log in).

After a succesful authentication, a cookie is made to keep track of their credential. 
So you don't have to!

Also checks for logout. If so, drops cookie, deletes CGI::Auth session file.

	$auth->check();

See CGI::Auth check() for more. Should always be called.



=head1 NEW METHODS

=head2 set_cookie_expire_time()

Default is +1h 
You can set the cookie expire time before check is called to change this value.

	my $auth = new CGI::Auth::Auto( ... );	
	$auth->set_cookie_expire_time('+15m');
	$auth->check;

Per the above example, if a cookie is made because user logged in, then it will be set to 15 minutes expiry
instead of the default 1 hour.

=head2 get_cookie_expire_time() 

Returns what the expiry was set at. I don't know why you may want this, but
it keeps people from having to check the internals. Returns '+1h' by default. If you 
have used set_cookie_expire() then it would return *that* value.


=head2 set_logout_param_name() and get_logout_param_name()

By default the logout field cgi parameter name is 'logout'. You can change the name this way:

	my $auth = new CGI::Auth::Auto( ... );	
	$auth->set_logout_param_name('elvis_has_left_the_building');
	$auth->check;

That means that http://mysite.com/cgi-bin/myapp.cgi?logout=1 will no longer log an authorized 
user out. But http://mysite.com/cgi-bin/myapp.cgi?elvis_has_left_the_building=1 will work 
instead.


=head2 logout()

Forces logout. Makes cookie expired and blank.
Then redirects to whatever CGI::Auth::Auto formaction was set to.
Then exit(0)s the script. You don't need to use this, likely, but it is here.
It is expected that logout() is called *after* authentication has been deemed true.


=head2 get_cgi()

Returns cgi object used, for re-use.

	my $cgi = $auth->get_cgi;

=head2 username()

Returns name of the user that logged. 
Actually returns field 0 of the sess file. 
Consult CGI::Auth for more on this.
Returns undef if no set.





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
		
		# ok drop this auth and log user out, will exit(0)
		$auth->logout;
	}
	
	# nothing wrong.. continue script..
	# ...


=head1 EXAMPLE SCRIPT

This example script is included in the distribution.
Example assumes you installed CGI::Auth support files in $ENV{DOCUMENT_ROOT}/../cgi-bin/auth

Make this $ENV{DOCUMENT_ROOT}/../cgi-bin/auth.cgi to test it. Don't forget chmod 0755.

	#!/usr/bin/perl -w
	BEGIN { use CGI::Carp qw(fatalsToBrowser); eval qq|use lib '$ENV{DOCUMENT_ROOT}/../lib';|; } # or wherever your lib is 
	use strict;
	use CGI::Auth::Auto;
	use CGI qw(:all);
	
	my $auth = new CGI::Auth::Auto({
		-authdir => "$ENV{DOCUMENT_ROOT}/../cgi-bin/auth"
	});
	$auth->check;
	
	print header();
	print start_html();
	
	print h1("hello ".$auth->username);
	
	print p('You are logged in now.');
	
	print p('Would you like to log out? <a href="'.$ENV{SCRIPT_NAME}.'?logout=1">logout</a>');	
	
	exit;


Parameter -authdir is where you have the CGI::Auth support files. You need the user.dat file there, etc.
See CGI::Auth for more.

=head1 BUGS

Please report bugs via email to author.


=head1 CHANGES

A previous temptation was to add CGI::Session automation in addition to the cookie system. 
This way, by simply using this module, you will have authentication and state maintained
for you. I consider this now out of scope here. after simply running check() you could safely
run CGI::Session::new() without fear of creating multiple sessions. Since check() already 
decided by that point that the user is truly authenticated.

A custom login.html template has been included in this distribution under cgi-bin/auth/login.html.
This template is minimal as compares to the candy one that comes with CGI::Auth. 


head1 SEE ALSO

CGI::Auth, CGI::Cookie, HTML::Template 

=head1 AUTHOR

Leo Charre leo (at) leocharre (dot) com

=cut
