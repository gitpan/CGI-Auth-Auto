# $Id: AuthCfg.pm,v 1.2 2006/10/08 12:14:39 cvs Exp $

package AuthCfg;
use Cwd;
use vars qw/$authcfg/;

# Basic Auth configuration, used by authman.pl and any web-based scripts.
$authcfg = {
	-authdir		=> cwd() ,
	-authfields		=> [
		{id => 'user', display => 'User Name', hidden => 0, required => 1},
		{id => 'pw', display => 'Password', hidden => 1, required => 1},
	],
};
