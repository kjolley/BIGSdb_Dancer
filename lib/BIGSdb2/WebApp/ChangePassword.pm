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
package BIGSdb2::WebApp::ChangePassword;
use strict;
use warnings;
use 5.010;
use Log::Log4perl qw(get_logger);
my $logger = get_logger('BIGSdb.Page');
use Dancer2 appname => 'BIGSdb2::WebApplication';
use Crypt::Eksblowfish::Bcrypt qw(bcrypt_hash en_base64);
use BIGSdb2::Constants qw(:authentication);
use BIGSdb2::Utils;
any [qw(get post)] => '/:db/changePassword' => sub { _change_password( { change => 1 } ) };
any [qw(get post)] => '/:db/setPassword'    => sub { _change_password( { set    => 1 } ) };

sub _change_password {
	my ($options) = @_;
	my $self = setting('self');
	my $title  = $options->{'change'} ? 'Change password' : 'Set user password';
	my $users  = _get_users();
	my $status = _check_submit_status($options);
	if ( params->{'submit'} && !$status->{'error'} ) {
		my $user_name = $options->{'set'} ? params->{'user'} : session('user');
		if ( _set_password_hash( $user_name, params->{'new_password1'} ) ) {
			if ($options->{'change'}){
				$status->{'success'} = q(Password updated ok.);
				session password_update_required => 0;
			} else {
				$status->{'success'} = qq(Password set for user '$user_name'.);
			}
			
			undef params->{'submit'};
		}
	}
	my $params = {
		title           => $title,
		javascript      => $self->get_javascript_libs( [qw(jQuery noCache CryptoJS.MD5)] ),
		min_length      => MIN_PASSWORD_LENGTH,
		users           => $users,
		form_action     => request->uri,
		no_continue     => $status->{'no_continue'},
		success         => $status->{'success'},
		error           => $status->{'error'},
		change_password => $options->{'change'},
		submit          => $self->get_action_fieldset( { no_reset => 1, submit_label => 'Set password' } ),
		index_route     => uri_for("/$self->{'instance'}")
	};
	return template 'change_password.tt', $params;
}

sub _check_submit_status {
	my ($options) = @_;
	my $self = setting('self');
	if (   $options->{'set'}
		&& !$self->{'permissions'}->{'set_user_passwords'}
		&& !$self->is_admin )
	{
		return { no_continue => 1, error => q(You are not allowed to change other users' passwords.) };
	}
	return if !params->{'submit'};
	if ( $options->{'set'} && !params->{'user'} ) {
		return { error => q(Please select a user.) };
	}
	if ( $options->{'change'} ) {
		my $status = _get_change_password_status();
		return $status if $status->{'error'};
	}
	if ( params->{'new_length'} < MIN_PASSWORD_LENGTH ) {
		my $min = MIN_PASSWORD_LENGTH;
		return { error => q(The password is too short and has not been updated. )
			  . qq(It must be at least $min characters long.) };
	}
	if ( params->{'new_password1'} ne params->{'new_password2'} ) {
		return { error => q(The password was not re-typed the same as the first time.) };
	}
	if ( params->{'existing_password'} eq params->{'new_password1'} ) {
		return { error => q(You must use a new password!) };
	}
	if ( params->{'username_as_password'} eq params->{'new_password1'} ) {
		return { error => q(You cannot use your username as your password!) };
	}
	return {};
}

sub _get_change_password_status {
	my $self = setting('self');
	if ( !$self->is_admin && params->{'user'} ) {
		my $subject_info = $self->{'datastore'}->get_user_info_from_username( params->{'user'} );
		if ( $subject_info && $subject_info->{'status'} eq 'admin' ) {
			return { error => q(You cannot change the password of an admin user unless you are an admin yourself.) };
		}
		if ( session('user') ne params->{'user'} ) {
			return {
				error => q(You are attempting to change another user's password. You are not allowed to do that!)
			};
		}
		my $stored_hash      = $self->get_password_hash( session('user') );
		my $password_matches = 1;
		if ( !$stored_hash->{'algorithm'} || $stored_hash->{'algorithm'} eq 'md5' ) {
			if ( $stored_hash->{'password'} ne params->{'existing_password'} ) {
				$password_matches = 0;
			}
		} elsif ( $stored_hash->{'algorithm'} eq 'bcrypt' ) {
			my $hashed_submitted_password = en_base64(
				bcrypt_hash(
					{ key_nul => 1, cost => $stored_hash->{'cost'}, salt => $stored_hash->{'salt'} },
					params->{'existing_password'}
				)
			);
			if ( $stored_hash->{'password'} ne $hashed_submitted_password ) {
				$password_matches = 0;
			}
		}
		if ( !$password_matches ) {
			return { error => q(Your existing password was entered incorrectly. The password has not been updated.) };
		}
	}
	return {};
}

sub _get_users {
	my $self = setting('self');
	my $user_data =
	  $self->{'datastore'}
	  ->run_query( 'SELECT user_name,first_name,surname FROM users WHERE id>0 ORDER BY lower(surname)',
		undef, { fetch => 'all_arrayref', slice => {} } );
	my $users = [];
	foreach my $user (@$user_data) {
		push @$users, { username => $user->{'user_name'}, fullname => "$user->{'surname'}, $user->{'first_name'}" };
	}
	return $users;
}

sub _set_password_hash {
	my ( $name, $hash ) = @_;
	my $self = setting('self');
	return if !$name;
	my $bcrypt_cost =
	  BIGSdb2::Utils::is_int( $self->{'config'}->{'bcrypt_cost'} ) ? $self->{'config'}->{'bcrypt_cost'} : BCRYPT_COST;
	my $salt = BIGSdb2::Utils::random_string( 16, { extended_chars => 1 } );
	my $bcrypt_hash = en_base64( bcrypt_hash( { key_nul => 1, cost => $bcrypt_cost, salt => $salt }, $hash ) );
	my $exists = $self->{'datastore'}->run_query(
		'SELECT EXISTS(SELECT * FROM users WHERE (dbase,name)=(?,?))',
		[ $self->{'system'}->{'db'}, $name ],
		{ db => $self->{'auth_db'} }
	);
	my $qry;

	if ( !$exists ) {
		$qry = 'INSERT INTO users (password,algorithm,cost,salt,reset_password,dbase,name) VALUES (?,?,?,?,?,?,?)';
	} else {
		$qry = 'UPDATE users SET (password,algorithm,cost,salt,reset_password)=(?,?,?,?,?) WHERE (dbase,name)=(?,?)';
	}
	eval {
		$self->{'auth_db'}
		  ->do( $qry, undef, $bcrypt_hash, 'bcrypt', $bcrypt_cost, $salt, undef, $self->{'system'}->{'db'}, $name );
	};
	if ($@) {
		$logger->error($@);
		$self->{'auth_db'}->rollback;
		return;
	} else {
		$self->{'auth_db'}->commit;
		return 1;
	}
}
1;
