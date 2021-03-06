#Written by Keith Jolley
#Copyright (c) 2010-2016, University of Oxford
#E-mail: keith.jolley@zoo.ox.ac.uk
#
#This file is part of Bacterial Isolate Genome Sequence Database (BIGSdb).
#
#BIGSdb is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#BIGSdb is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with BIGSdb.  If not, see <http://www.gnu.org/licenses/>.
#
#perl-md5-login used as basis.  Extensively modified for BIGSdb.
#Javascript md5 now provided by CryptoJS (code.google.com/p/crypto-js)
#as a separate file.
#
#Copyright for perl-md5-login is below.
########################################################################
#
# perl-md5-login: a Perl/CGI + JavaScript user authorization
#
# This software is provided 'as-is' and without warranty. Use it at
# your own risk.
#
# SourceForge project: http://perl-md5-login.sourceforge.net/
#
# Perl/CGI interface Copyright 2003 Alan Raetz <alanraetz@chicodigital.com>
# Released under the LGPL license (see http://www.fsf.org)
#
# The original Digest::MD5 Perl Module interface was written by
# Neil Winton <N.Winton@axion.bt.co.uk> and is maintained by
# Gisle Aas <gisle@ActiveState.com>
package BIGSdb2::WebApp::Login;
use strict;
use warnings;
use 5.010;
use Digest::MD5;
use Crypt::Eksblowfish::Bcrypt qw(bcrypt_hash en_base64);
use Log::Log4perl qw(get_logger);
my $logger = get_logger('BIGSdb.Application_Authentication');
use BIGSdb2::Constants qw(:authentication);
use Dancer2 appname => 'BIGSdb2::WebApplication';
any [qw(get post)] => '/:db/login' => sub { _login() };
get '/:db/logout' => sub { _logout() };

sub _login {
	my $self = setting('self');
	setting session_id => Digest::MD5::md5_hex( request->address . int( rand(4294967296) ) . UNIQUE_STRING );
	my ( $user, $reset_password ) = _secure_login();
	if ($user) {
		session user => $user;
		session db   => $self->{'instance'};
		params->{'route'} //= q();
		my $route = uri_for( "/$self->{'instance'}" . params->{'route'} );
		redirect $route;
	}
	my $desc = $self->get_db_description() || 'BIGSdb';
	if ( !params->{'session'} || !_login_session_exists( params->{'session'} ) ) {
		_create_session( setting('session_id'), 'login', undef );
	}
	my $params = {
		title        => "Log in - $desc",
		desc         => $desc,
		banner       => $self->get_file_text("$self->{'config_dir'}/dbases/$self->{'instance'}/banner.html"),
		registration => $self->get_file_text("$self->{'config_dir'}/dbases/$self->{'instance'}/registration.html"),
		error        => setting('error'),
		session_id   => setting('session_id'),
		javascript   => $self->get_javascript_libs( [qw(jQuery noCache CryptoJS.MD5)] ),
		form_action  => request->uri,
		route        => setting('return_url'),
		submit       => $self->get_action_fieldset( { no_reset => 1, submit_label => 'Log in' } )
	};
	return template 'login.tt', $params;
}

sub _login_session_exists {
	my ($session) = @_;
	my $self = setting('self');
	return $self->{'datastore'}->run_query(
		'SELECT EXISTS(SELECT * FROM sessions WHERE (dbase,session,state)=(?,md5(?),?))',
		[ $self->{'system'}->{'db'}, $session, 'login' ],
		{ db => $self->{'auth_db'}, cache => 'Login::login_session_exists' }
	);
}

sub _secure_login {
	my $self = setting('self');
	my ( $user, $password_hash ) = _MD5_login();
	return if !$user;
	######################################################
	# If they've gotten to this point, they have been
	# authorized against the database (they
	# correctly filled in the name/password field)
	# so store their current IP address in the database
	######################################################
	my $ip_addr = $self->get_ip_address;
	_set_current_user_IP_address( $user, $ip_addr );
	######################################################
	# Set Cookie information with a session timeout
	######################################################
	my $setCookieString = Digest::MD5::md5_hex( $ip_addr . $password_hash . UNIQUE_STRING );
	my $session_cookie  = "$self->{'system'}->{'db'}_session";
	my $pass_cookie     = "$self->{'system'}->{'db'}_auth";
	my $user_cookie     = "$self->{'system'}->{'db'}_user";
	my $cookies = { $session_cookie => params->{'session'}, $pass_cookie => $setCookieString, $user_cookie => $user };
	_create_session( params->{'session'}, 'active', $user, $self->{'reset_password'} );
	_set_cookies( $cookies, COOKIE_TIMEOUT );
	return ( $user, $self->{'reset_password'} );    # SUCCESS, w/cookie header
}

sub _MD5_login {
	my $self = setting('self');
	_timeout_logins();                              # remove entries older than current_time + $timeout
	if ( params->{'submit'} ) {
		if ( my $password = _check_password() ) {
			$logger->info( 'User ' . param('user') . " logged in to $self->{'instance'}." );
			_delete_session( params->{'session'} );
			return ( param('user'), $password );    # return user name and password hash
		}
	}
}

sub _check_password {
	my $self = setting('self');
	if ( !params->{'user'} )     { set error => 'The name field was missing.' }
	if ( !params->{'password'} ) { set error => 'The password field was missing.' }
	my $login_session_exists = _login_session_exists( params->{'session'} );
	if ( !$login_session_exists ) { set error => 'The login window has expired - please resubmit credentials.' }
	my $stored_hash = $self->get_password_hash( params->{'user'} ) // '';
	if ( !$stored_hash ) {
		_delete_session( params->{'session'} );
		set error => 'Invalid username or password entered.  Please try again.';
		return;
	}
	$logger->debug( 'using session ID = ' . params->{'session'} );
	$logger->debug( 'Saved password hash for ' . params->{'user'} . ' = ' . $stored_hash->{'password'} );
	$logger->debug( 'Submitted password hash for ' . params->{'user'} . ' = ' . params->{'password'} );

	# Compare the calculated hash based on the saved password to
	# the hash returned by the form submission: they must match
	my $password_matches = 1;
	if ( !$stored_hash->{'algorithm'} || $stored_hash->{'algorithm'} eq 'md5' ) {
		if ( $stored_hash->{'password'} ne params->{'password'} ) {
			$password_matches = 0;
		}
	} elsif ( $stored_hash->{'algorithm'} eq 'bcrypt' ) {
		my $hashed_submitted_password = en_base64(
			bcrypt_hash(
				{ key_nul => 1, cost => $stored_hash->{'cost'}, salt => $stored_hash->{'salt'} },
				params->{'password'}
			)
		);
		if ( $stored_hash->{'password'} ne $hashed_submitted_password ) {
			$password_matches = 0;
		}
	} else {
		$password_matches = 0;
	}
	if ( !$password_matches ) {
		_delete_session( params->{'session'} );
		set error => 'Invalid username or password entered.  Please try again.';
	} else {
		if ( $stored_hash->{'reset_password'} ) {
			$logger->info('Password reset required.');
			$self->{'reset_password'} = 1;
		}
		return $stored_hash->{'password'};
	}
	return;
}

sub _logout {
	my $self           = setting('self');
	my $session_cookie = "$self->{'system'}->{'db'}_session";
	my $session_id     = $self->get_cookie($session_cookie);
	_delete_session($session_id);
	redirect uri_for("/$self->{'instance'}");
	return;
}

sub _set_current_user_IP_address {
	my ( $user_name, $ip_address ) = @_;
	my $self = setting('self');
	eval {
		$self->{'auth_db'}->do( 'UPDATE users SET ip_address=? WHERE (dbase,name)=(?,?)',
			undef, $ip_address, $self->{'system'}->{'db'}, $user_name );
	};
	if ($@) {
		$logger->error($@);
		$self->{'auth_db'}->rollback;
	} else {
		$self->{'auth_db'}->commit;
	}
	return;
}

#Store session as a MD5 hash of passed session.  This should prevent someone
#with access to the auth database from easily using active session tokens.
sub _create_session {
	my ( $session, $state, $username, $reset_password ) = @_;
	my $self   = setting('self');
	my $exists = $self->{'datastore'}->run_query(
		'SELECT EXISTS(SELECT * FROM sessions WHERE dbase=? AND session=md5(?))',
		[ $self->{'system'}->{'db'}, $session ],
		{ db => $self->{'auth_db'} }
	);
	return if $exists;
	eval {
		$self->{'auth_db'}->do(
			'INSERT INTO sessions (dbase,session,start_time,state,username,reset_password) VALUES (?,md5(?),?,?,?,?)',
			undef, $self->{'system'}->{'db'},
			$session, time, $state, $username, $reset_password
		);
	};
	if ($@) {
		$logger->error($@);
		$self->{'auth_db'}->rollback;
	} else {
		$logger->debug("$state session created: $session");
		$self->{'auth_db'}->commit;
	}
	foreach my $param (qw(password_field password session user submit)) {
		undef params->{$_};
	}
	return;
}

sub _delete_session {
	my ($session_id) = @_;
	my $self = setting('self');
	eval { $self->{'auth_db'}->do( 'DELETE FROM sessions WHERE session=md5(?)', undef, $session_id ); };
	if ($@) {
		$logger->error($@);
		$self->{'auth_db'}->rollback;
	} else {
		$self->{'auth_db'}->commit;
	}
	return;
}

sub _set_cookies {
	my ( $cookie_values, $expires ) = @_;
	foreach my $cookie ( keys %$cookie_values ) {
		cookie( $cookie => $cookie_values->{$cookie}, expires => $expires );
	}
	return;
}

#Do this for all databases
sub _timeout_logins {
	my $self = setting('self');
	eval {
		$self->{'auth_db'}
		  ->do( 'DELETE FROM sessions WHERE start_time<? AND state=?', undef, ( time - LOGIN_TIMEOUT ), 'login' );
	};
	if ($@) {
		$logger->error($@);
		$self->{'auth_db'}->rollback;
	} else {
		$self->{'auth_db'}->commit;
	}
	return;
}
1;
