#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'WWW::Google::Auth::ClientLogin' ) || print "Bail out!
";
}

diag( "Testing WWW::Google::Auth::ClientLogin $WWW::Google::Auth::ClientLogin::VERSION, Perl $], $^X" );
