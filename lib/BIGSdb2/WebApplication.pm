#Written by Keith Jolley
#(c) 2010-2016, University of Oxford
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
package BIGSdb2::WebApplication;
use strict;
use warnings;
use 5.010;
use parent qw(BIGSdb2::Application);
use Dancer2;
use Config::Tiny;
use Try::Tiny;
use List::MoreUtils qw(uniq);
use Digest::MD5;
use Log::Log4perl qw(get_logger);
my $logger = get_logger('BIGSdb.Application_Initiate');
use BIGSdb2::WebApp::Login;
use BIGSdb2::WebApp::Query::Index;
use BIGSdb2::Constants qw(:interface :authentication);
hook before                 => sub { _before() };
hook after                  => sub { _after() };
hook before_template_render => sub { _before_template() };

sub initiate {
	my ($self) = @_;
	$self->read_config_file( $self->{'config_dir'} );
	$self->read_host_mapping_file( $self->{'config_dir'} );
	set template => 'template_toolkit';
	set views    => path( dirname(__FILE__), '../../templates' );
	set layout   => 'main';
	set self     => $self;
	return;
}

#Read database configs and connect before entering route.
sub _before {
	my $self        = setting('self');
	my $request_uri = request->uri;
	$self->{'instance'} = $request_uri =~ /^\/([\w\d\-_]+)/x ? $1 : '';
	my $full_path = "$self->{'config_dir'}/dbases/$self->{'instance'}/config.xml";
	if ( !$self->{'instance'} ) {
		send_error( 'No database selected.', 404 );
	} elsif ( !-e $full_path ) {
		send_error( "Database $self->{'instance'} has not been defined", 404 );
	} else {
		$self->{'xmlHandler'} = BIGSdb2::Parser->new;
		my $parser = XML::Parser::PerlSAX->new( Handler => $self->{'xmlHandler'} );
		eval { $parser->parse( Source => { SystemId => $full_path } ) };
		if ($@) {
			$logger->fatal("Invalid XML description: $@") if $self->{'instance'} ne '';
			undef $self->{'system'};
			return;
		}
		$self->{'system'} = $self->{'xmlHandler'}->get_system_hash;
	}
	$self->set_system_overrides;
	$ENV{'PATH'} = '/bin:/usr/bin';    ## no critic (RequireLocalizedPunctuationVars) #so we don't foul taint check
	delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};    # Make %ENV safer
	$self->{'system'}->{'read_access'} //= 'public';                                      #everyone can view by default
	$self->{'system'}->{'host'}        //= $self->{'config'}->{'host'} // 'localhost';
	$self->{'system'}->{'port'}        //= $self->{'config'}->{'port'} // 5432;
	$self->{'system'}->{'user'}        //= $self->{'config'}->{'user'} // 'apache';
	$self->{'system'}->{'password'}    //= $self->{'config'}->{'password'} // 'remote';

	if ( ( $self->{'system'}->{'dbtype'} // '' ) eq 'isolates' ) {
		$self->{'system'}->{'view'}       //= 'isolates';
		$self->{'system'}->{'labelfield'} //= 'isolate';
		if ( !$self->{'xmlHandler'}->is_field( $self->{'system'}->{'labelfield'} ) ) {
			$logger->error( "The defined labelfield '$self->{'system'}->{'labelfield'}' does not exist in the "
				  . 'database. Please set the labelfield attribute in the system tag of the database XML file.' );
		}
	}
	$self->{'dataConnector'}->initiate( $self->{'system'}, $self->{'config'} );
	$self->db_connect;
	send_error( 'No access to databases - undergoing maintenance.', 503 ) if !$self->{'db'};
	$self->initiate_authdb if ( $self->{'system'}->{'authentication'} // '' ) eq 'builtin';
	$self->setup_datastore;

	#	$self->_initiate_view;
	my $authenticated_db = ( $self->{'system'}->{'read_access'} // '' ) ne 'public';
	my $login_route      = "/$self->{'instance'}/login";
	my $logout_route     = "/$self->{'instance'}/logout";

	#	my $submission_route = "/db/$self->{'instance'}/submissions";
	#	if ( $request_uri =~ /$submission_route/x ) {
	#		$self->setup_submission_handler;
	#	}
	if ( ( $authenticated_db && $request_uri !~ /^$login_route/x && $request_uri !~ /^$logout_route/x ) ) {
		send_error( 'Unauthorized', 401 ) if !$self->_is_authorized;
	}
	return;
}

#Drop the connection because we may have hundreds of databases on the system.
#Keeping them all open will exhaust resources.
sub _after {
	my $self = setting('self');
	$self->{'dataConnector'}->drop_all_connections;
	return;
}

sub _before_template {
	my ($tokens) = @_;
	$tokens->{'uri_base'} = request->base->path;
	return;
}

sub get_javascript_libs {
	my ( $self, $features ) = @_;
	my @javascript;
	my %features = map { $_ => 1 } @$features;
	if ( $features{'jQuery'} ) {
		if ( $self->{'config'}->{'intranet'} eq 'yes' ) {
			push @javascript, q(src="/javascript/jquery.js" type="text/Javascript");
			push @javascript, q(src="/javascript/jquery-ui.js" type="text/Javascript");
		} else {

			#Load jQuery library from Google CDN
			push @javascript,
			  q(src="http://ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js" type="text/Javascript");
			push @javascript,
			  q(src="http://ajax.googleapis.com/ajax/libs/jqueryui/1.10.2/jquery-ui.min.js" type="text/Javascript");
		}
		push @javascript, (q(src="/javascript/bigsdb.js?v20160621" type="text/Javascript"));
	}
	my %js_libs = (
		'jQuery.tablesort'    => [qw(jquery.tablesorter.js jquery.metadata.js)],
		'jQuery.jstree'       => [qw(jquery.jstree.js jquery.cookie.js jquery.hotkeys.js)],
		'jQuery.coolfieldset' => [qw(jquery.coolfieldset.js)],
		'jQuery.slimbox'      => [qw(jquery.slimbox2.js)],
		'jQuery.columnizer'   => [qw(jquery.columnizer.js)],
		'jQuery.multiselect'  => [qw(modernizr.js jquery.multiselect.js)],
		'CryptoJS.MD5'        => [qw(md5.js)]
	);
	foreach my $js_lib ( keys %js_libs ) {
		next if !$features{$js_lib};
		my $libs = $js_libs{$js_lib};
		push @javascript, qq(src="/javascript/$_" type="text/Javascript") foreach @$libs;
	}
	local $" = qq(></script>\n<script );
	return qq(<script @javascript></script>);
}

sub get_action_fieldset {
	my ( $self, $options ) = @_;
	$options = {} if ref $options ne 'HASH';
	my $submit_label = $options->{'submit_label'} // 'Submit';
	my $reset_label  = $options->{'reset_label'}  // 'Reset';
	my $legend       = $options->{'legend'}       // 'Action';
	my $buffer       = qq(<fieldset style="float:left"><legend>$legend</legend>\n);
	my $url          = request->uri;
	my @fields = qw (isolate_id id scheme_id table name ruleset locus profile_id simple set_id modify);

	if ( $options->{'table'} ) {
		my $pk_fields = $self->{'datastore'}->get_table_pks( $options->{'table'} );
		push @fields, @$pk_fields;
	}
	foreach ( uniq @fields ) {
		$url .= "&amp;$_=$options->{$_}" if defined $options->{$_};
	}

	#use jquery-ui button classes to ensure consistent formatting of reset link and submit button across browsers
	if ( !$options->{'no_reset'} ) {
		my $class = RESET_BUTTON_CLASS;
		$buffer .= qq(<a href="$url" class="$class ui-button-text-only">)
		  . qq(<span class="ui-button-text">$reset_label</span></a>\n);
	}
	my $class = BUTTON_CLASS;
	$buffer .= qq(<input type="submit" name="submit" value="Log in" class="$class" />\n);
	$buffer .= q(</fieldset><div style="clear:both"></div>);
	return $buffer;
}
###############
#Authentication
###############
sub _is_authorized {
	my ($self) = @_;
	$self->_cookie_login;
	my $route = request->uri;
	if ( session('user') ) {
		my $user_info = $self->{'datastore'}->get_user_info_from_username( session('user') );
		session full_name => "$user_info->{'first_name'} $user_info->{'surname'}";
		if ( $route =~ /login$/x ) {
			$route = "/$self->{'instance'}";
		}
		return 1;
	}

	#Strip off database part of route to prevent someone logging
	#in to one database and changing the route parameter by editing form.
	$route =~ s/^\/$self->{'instance'}//x;
	setting return_url => $route;
	try {
		redirect( uri_for("/$self->{'instance'}/login") );
	}
	catch {
		send_error( $self->{'authenticate_error'}, 401 );
	};
	return;
}

sub get_ip_address {
	my ($self) = @_;
	my $ip_addr = request->address;
	$ip_addr =~ s/\.\d+$//x;
	return $ip_addr;
}

sub _cookie_login {
	my ($self) = @_;

	#Create per database cookies to prevent problems when opening two sessions with
	#different credentials.
	my $session_cookie = "$self->{'system'}->{'db'}_session";
	my $user_cookie    = "$self->{'system'}->{'db'}_user";
	$self->_timout_sessions();
	my $stored_hash = $self->get_password_hash( $self->get_cookie($user_cookie) ) // '';
	if ( !$stored_hash ) {
		return;
	}
	my $saved_IP_address = $self->_get_saved_IP_address( $self->get_cookie($user_cookie) ) // '';
	my $ip_addr          = $self->get_ip_address;
	my $cookie_string    = Digest::MD5::md5_hex( $ip_addr . $stored_hash->{'password'} . UNIQUE_STRING );
	##############################################################
	# Test the cookies against the current database
	##############################################################
	# If the current IP address matches the saved IP address
	# and the current cookie hash matches the saved cookie hash
	# we allow access.
	##############################################################
	my $pass_cookie = $self->get_cookie("$self->{'system'}->{'db'}_auth");
	if (   $stored_hash->{'password'}
		&& $saved_IP_address eq $ip_addr
		&& $pass_cookie      eq $cookie_string
		&& $self->_active_session_exists( $self->get_cookie($session_cookie), $self->get_cookie($user_cookie) ) )
	{
		$logger->debug('User cookie validated, allowing access.');
		if ( $self->_password_reset_required( $self->get_cookie($session_cookie), $self->get_cookie($user_cookie) ) ) {
			session password_update_required => 1;
		}

		# good cookie, allow access
		session user => $self->get_cookie($user_cookie);
		session db   => $self->{'instance'};
	}
	return;
}

sub get_cookie {
	my ( $self, $name ) = @_;
	my $cookie = cookies->{$name};
	if ( ref $cookie ) {
		return $cookie->value // q();
	}
	return q();
}

#Do this for all databases and for both login and active sessions since
#active session timeout is longer than login timeout.
sub _timout_sessions {
	my ($self) = @_;
	eval { $self->{'auth_db'}->do( 'DELETE FROM sessions WHERE start_time<?', undef, ( time - SESSION_TIMEOUT ) ) };
	if ($@) {
		$logger->error($@);
		$self->{'auth_db'}->rollback;
	} else {
		$self->{'auth_db'}->commit;
	}
	return;
}

#Do this for all databases
sub timeout_logins {
	my ($self) = @_;
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

sub get_password_hash {
	my ( $self, $name ) = @_;
	return if !$name;
	my $password = $self->{'datastore'}->run_query(
		'SELECT password,algorithm,salt,cost,reset_password FROM users WHERE dbase=? AND name=?',
		[ $self->{'system'}->{'db'}, $name ],
		{ db => $self->{'auth_db'}, fetch => 'row_hashref' }
	);
	return $password;
}

sub _get_saved_IP_address {
	my ( $self, $name ) = @_;
	return if !$name;
	my $ip_address = $self->{'datastore'}->run_query(
		'SELECT ip_address FROM users WHERE dbase=? AND name=?',
		[ $self->{'system'}->{'db'}, $name ],
		{ db => $self->{'auth_db'} }
	);
	return $ip_address;
}

sub _active_session_exists {
	my ( $self, $session, $username ) = @_;
	my $md5_session = Digest::MD5::md5_hex($session);
	return $self->{'datastore'}->run_query(
		'SELECT EXISTS(SELECT * FROM sessions WHERE (dbase,session,state,username)=(?,md5(?),?,?))',
		[ $self->{'system'}->{'db'}, $session, 'active', $username ],
		{ db => $self->{'auth_db'}, cache => 'Login::active_session_exists' }
	);
}

sub set_cookies {
	my ( $self, $cookie_values, $expires ) = @_;
	foreach my $cookie ( keys %$cookie_values ) {
		cookie( $cookie => $cookie_values->{$cookie}, expires => $expires );
	}
	return;
}

sub _password_reset_required {
	my ( $self, $session, $username ) = @_;
	return $self->{'datastore'}->run_query(
		'SELECT EXISTS(SELECT * FROM sessions WHERE (dbase,session,state,username)=(?,md5(?),?,?) AND reset_password)',
		[ $self->{'system'}->{'db'}, $session, 'active', $username ],
		{ db => $self->{'auth_db'}, cache => 'Login::password_reset_required' }
	);
}

sub create_session {

	#Store session as a MD5 hash of passed session.  This should prevent someone with access to the auth database
	#from easily using active session tokens.
	my ( $self, $session, $state, $username, $reset_password ) = @_;
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

sub delete_session {
	my ( $self, $session_id ) = @_;
	eval { $self->{'auth_db'}->do( 'DELETE FROM sessions WHERE session=md5(?)', undef, $session_id ); };
	if ($@) {
		$logger->error($@);
		$self->{'auth_db'}->rollback;
	} else {
		$self->{'auth_db'}->commit;
	}
	return;
}

sub set_current_user_IP_address {
	my ( $self, $user_name, $ip_address ) = @_;
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
1;
