use ExtUtils::MakeMaker;
WriteMakefile(
    NAME              => 'CGI::Auth::Auto',
    VERSION_FROM      => 'lib/CGI/Auth/Auto.pm', # finds $VERSION
    PREREQ_PM         => { 
		'CGI::Auth' => 0,
		'HTML::Template' => 0,
		}, 
);
