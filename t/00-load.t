#!perl -T

use Test::More tests => 2;

BEGIN {
	use_ok( 'Symantec::PCAnywhere::Profile' );
	use_ok( 'Symantec::PCAnywhere::Profile::CHF' );
}

diag( "Testing Symantec::PCAnywhere::Profile $Symantec::PCAnywhere::Profile::VERSION, Perl $], $^X" );
