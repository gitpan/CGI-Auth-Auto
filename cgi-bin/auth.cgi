#!/usr/bin/perl -w
BEGIN { use CGI::Carp qw(fatalsToBrowser); eval qq|use lib '$ENV{DOCUMENT_ROOT}/../lib';|; } # or wherever your lib is 
use strict;
use CGI::Auth::Auto;
use CGI;
my $c = new CGI;

my $auth = new CGI::Auth::Auto({
	-formaction => '/cgi-bin/auth.cgi', # this script as from http
	-cgi => $c,	# not a must, this is to we don't recreate the cgi object in CGI::Auth	
   -authdir                => $ENV{DOCUMENT_ROOT}.'/../cgi-bin/auth', # provided this *is* where the supporting files reside - will not work if it's not absolute here, hence the /../
   -authfields             => [
            {id => 'user', display => 'User Name', hidden => 0, required => 1},
            {id => 'pw', display => 'Password', hidden => 1, required => 1},
        ],
});

$auth->check;


my $name = $auth->OpenSessionFile;
$name ||= 'none'; # you can get the user name.. see CGI::Auth for details

print $c->header;
print $c->start_html;
print $c->p("ok $name, you're in");

print $c->p('<a href="/cgi-bin/auth.cgi?logout=1">[logout]</a>');

exit;













