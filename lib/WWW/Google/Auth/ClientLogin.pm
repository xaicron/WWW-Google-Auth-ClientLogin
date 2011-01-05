package WWW::Google::Auth::ClientLogin;

use Carp;
use LWP::UserAgent;
use HTTP::Request::Common;

use warnings;
use strict;

=head1 NAME

WWW::Google::Auth::ClientLogin - Support module to Google ClientLogin authorization

=head1 SYNOPSIS

    use WWW::Google::Auth::ClientLogin;

    my $auth = WWW::Google::Auth::ClientLogin -> new(
		email 		=> 'user@gmail.com',
		password 	=> 'UserPassword',
		source		=> 'MyApp-0.8',
		type		=> 'GOOGLE',
		service 	=> 'writely');
		
    my $auth_token = $auth -> authenticate -> {'Auth'};

=head1 DESCRIPTION

This module implements the support to Google's ClientLogin authentication
method for Goodle Data Protocol.


=head1 METHODS

=head2 new

Is the contructor for the WWW::Google::Auth::ClientLogin object. Takes
as parameters the following variables:

=over

=item B<email>

Specifies the user's full email address..  

=item B<password>

Specifies the user's password. 

=item B<source>

Specifies a string identifying your application (optional).

=item B<type> (default to HOSTED_OR_GOOGLE)

Specifies the type of the account to request authorization for (optional, 
default to HOSTED_OR_GOOGLE).

Possible values are GOOGLE, HOSTED or HOSTED_OR_GOOGLE (default).

=item B<service>

Specifies the service to request authorization for.

A list of available services can be found at L<http://code.google.com/intl/en/apis/base/faq_gdata.html#clientlogin>.

=item B<token>

Specifies the CAPTCHA token received after a login failure with the error
code 'CaptchaRequired' (optional).

=item B<captcha>

Specifies the user's answer to the CAPTCHA challenge identified by
"token" (optional).

=back

=cut

sub new {
	my $class  = shift;
	my %params = @_;
	my $self   = {};

	$self -> {'email'} = $params{'email'} || croak("Err: set a valid email");
	$self -> {'pwd'}   = $params{'password'} || croak("Err: set a password");
	$self -> {'src'}   = $params{'source'} || __PACKAGE__ . $__PACKAGE__::VERSION;

	my @valid_account_types = ('GOOGLE', 'HOSTED', 'HOSTED_OR_GOOGLE');

	if ($params{'type'} and grep {$_ eq $params{'type'}} @valid_account_types) {
		$self -> {'type'} = $params{'type'};
	} else {
		$self -> {'type'} = 'HOSTED_OR_GOOGLE';
	}

	my @valid_services = ('analytics', 'apps', 'gbase', 'jotspot', 
			      'blogger', 'print', 'cl', 'codesearch', 'cp', 
			      'writely', 'finance', 'mail', 'health', 'weaver',
			      'local', 'lh2', 'annotateweb', 'wise', 'sitemaps',
			      'youtube');

	if (grep {$_ eq $params{'service'}} @valid_services) {
		$self -> {'service'} = $params{'service'};
	} else {
		croak("Err: set a valid service");
	}

    bless($self, $class);

    return $self;
}


=head2 authenticate( )

Send the authentication request.

It returns an anonymous hash containing the following values:

=over

=item B<status>

Set to 0 if authentication succeded, -1 if not.

=item B<Auth>

Authentication token (set if authentication succeded).

=item B<error>

Error code (set if authentication failed).

A list of error codes can be found at L<http://code.google.com/intl/it-IT/apis/accounts/docs/AuthForInstalledApps.html#Errors>.

=item B<captcha_token>

The token specified to a CAPTCHA challenge (set if error code is 'CaptchaRequired').

=item B<captcha_url>

Url pointing to the CAPTCHA image to be show n to user. Must be prefixed 
with 'http://www.google.com/accounts/' (set if error code is 'CaptchaRequired').

=back

=cut

sub authenticate {
	my $self = shift;

	my $ua = LWP::UserAgent -> new;
	my $url = 'https://www.google.com/accounts/ClientLogin';

	my %params = ('accountType', 	$self -> {'type'},
		      'Email',		$self -> {'email'},
		      'Passwd',		$self -> {'pwd'},
		      'service',	$self -> {'service'},
		      'source',		$self -> {'source'});

	my $response 	= $ua -> request(POST $url, [%form]) -> as_string;

	my $status  	= (split / /,(split /\n/, $response)[0])[1];
	my $body	= (split /\n\n/, $response)[1];

	my $out = {};

	if ($status == 200) {
		$out -> {'status'} = 0;

		$body =~ m/SID=(.*)\nLSID=(.*)\nAuth=(.*)\n/;

		#$out -> {'SID'}    = $1;
		#$out -> {'LSID'}   = $2;
		$out -> {'Auth'}   = $3;
	} elsif ($status == 403) {
		$out -> {'status'} = -1;

		$body =~ m/Error=(.*)\n/;
		$out -> {'error'}  = $1;

		if ($out -> {'error'} eq 'CaptchaRequired') {
			$body =~ /CaptchaToken=(.*)\nCaptchaUrl==(.*)\n/;

			$out -> {'captcha_token'} = $1;
			$out -> {'captcha_url'}   = $2;
		}
	}

	return $out;
}

=head1 AUTHOR

Alessandro Ghedini <alexbio@cpan.org>

=head1 BUGS

Please report any bugs or feature requests at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=WWW-Google-Auth-ClientLogin>.
I will be notified, and then you'll automatically be notified of progress 
on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc WWW::Google::Auth::ClientLogin

You can also look for information at:

=over 4

=item * GitHub page

L<http://github.com/AlexBio/WWW-Google-Auth-ClientLogin>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=WWW-Google-Auth-ClientLogin>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/WWW-Google-Auth-ClientLogin>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/WWW-Google-Auth-ClientLogin>

=item * Search CPAN

L<http://search.cpan.org/dist/WWW-Google-Auth-ClientLogin/>

=back

=head1 LICENSE AND COPYRIGHT

Copyright 2011 Alessandro Ghedini.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

1; # End of WWW::Google::Auth::ClientLogin
