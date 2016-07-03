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
use Dancer2::Core::Error;
use Config::Tiny;
use Try::Tiny;
use List::MoreUtils qw(uniq none);
use Digest::MD5;
use Log::Log4perl qw(get_logger);
my $logger = get_logger('BIGSdb.Application_Initiate');
use BIGSdb2::WebApp::About;
use BIGSdb2::WebApp::ChangePassword;
use BIGSdb2::WebApp::Login;
use BIGSdb2::WebApp::Preferences;
use BIGSdb2::WebApp::Public::Index;
use BIGSdb2::WebApp::Public::Query;
use BIGSdb2::Constants qw(:interface :authentication);
hook before                 => sub { _before() };
hook after                  => sub { _after() };
hook before_template_render => sub { _before_template() };
any qr/.*/x                 => sub {
	my $self = setting('self');
	$self->throw_error(
		{
			status         => 404,
			message        => 'Page not found',
			no_status_desc => 1,
			details        => 'Unknown function requested - either an incorrect link brought you here or '
			  . 'this functionality has not been implemented yet'
		}
	);
};

sub initiate {
	my ($self) = @_;
	$self->read_config_file( $self->{'config_dir'} );
	$self->read_host_mapping_file( $self->{'config_dir'} );
	set template => 'template_toolkit';
	set views    => path( dirname(__FILE__), '../../templates' );
	set layout   => 'main';
	my $path        = "$self->{'config_dir'}/templates";
	my $header_file = "$path/site_header.tt";
	setting site_header => $header_file if -e $header_file;
	my $footer_file = "$path/site_footer.tt";
	setting site_footer => $footer_file if -e $footer_file;
	set self => $self;
	return;
}

#Read database configs and connect before entering route.
sub _before {
	my $self = setting('self');

	#TODO Check file upload size and limit if needed
	my $request_uri = request->uri;
	$self->{'instance'} = $request_uri =~ /^\/([\w\d\-_]+)/x ? $1 : '';
	my $full_path = "$self->{'config_dir'}/dbases/$self->{'instance'}/config.xml";
	if ( !$self->{'instance'} ) {
		return;    #No database - just return landing page.
	} elsif ( !-e $full_path ) {
		$self->throw_error(
			{
				status  => 404,
				message => 'Database configuration not defined',
				details => "No configuration called '$self->{'instance'}' exists.",
				error   => "Database config file for '$self->{'instance'}' does not exist."
			}
		);
	} else {
		$self->{'xmlHandler'} = BIGSdb2::Parser->new;
		my $parser = XML::Parser::PerlSAX->new( Handler => $self->{'xmlHandler'} );
		eval { $parser->parse( Source => { SystemId => $full_path } ) };
		if ($@) {
			undef $self->{'system'};
			$self->throw_error(
				{
					status  => 500,
					message => 'Invalid XML description',
					details => 'The config XML file for this database configuration is malformed.',
					error   => $@
				}
			);
		}
		$self->{'system'} = $self->{'xmlHandler'}->get_system_hash;
	}
	$self->set_system_overrides;
	if ( !defined $self->{'system'}->{'dbtype'}
		|| ( $self->{'system'}->{'dbtype'} ne 'sequences' && $self->{'system'}->{'dbtype'} ne 'isolates' ) )
	{
		$self->throw_error(
			{
				status  => 500,
				message => 'Invalid database type specified',
				details => q(Please set dbtype to either 'isolates' or 'sequences' in the system )
				  . q(attributes of the XML description file for this database.),
				error => $@
			}
		);
	}
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
	if ( !$self->{'db'} ) {
		$self->throw_error(
			{
				status  => 503,
				message => 'No access to databases',
				details => 'The system is currently undergoing maintenance.',
			}
		);
	}
	try {
		$self->initiate_authdb;
	}
	catch {
		$self->throw_error( { status => 500, message => 'Cannot connect to authentication database!', } );
	};
	$self->setup_datastore;
	$self->_setup_prefstore;

	#	$self->_initiate_view;
	return if request->is_ajax;
	my $authenticated_db = ( $self->{'system'}->{'read_access'} // '' ) ne 'public';
	my $login_route      = "/$self->{'instance'}/login";
	my $logout_route     = "/$self->{'instance'}/logout";
	if ( ( $authenticated_db && $request_uri !~ /^$login_route/x && $request_uri !~ /^$logout_route/x ) ) {
		send_error( 'Unauthorized', 401 ) if !$self->_is_authorized;
		$self->{'permissions'} = $self->{'datastore'}->get_permissions( session('user') );
		my $change_password_route = "/$self->{'instance'}/changePassword";
		if ( session('password_update_required') && $request_uri !~ /$change_password_route/x ) {
			redirect( uri_for("/$self->{'instance'}/changePassword") );
		}
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
	$buffer .= qq(<input type="submit" name="submit" value="$submit_label" class="$class" />\n);
	$buffer .= q(</fieldset><div style="clear:both"></div>);
	return $buffer;
}

sub is_admin {
	my ($self) = @_;
	if ( session('user') ) {
		my $status = $self->{'datastore'}->run_query( 'SELECT status FROM users WHERE user_name=?',
			session('user'), { cache => 'WebApplication::is_admin' } );
		return if !$status;
		return 1 if $status eq 'admin';
	}
	return;
}

sub throw_error {
	my ( $self, $options ) = @_;
	$options->{'status'}  //= 500;
	$options->{'message'} //= q(BIGSdb has encountered an unspecified error.);
	$options->{'details'} //= q();
	$logger->error( $options->{'error'} ) if $options->{'error'};
	my $status_desc =
	  { 401 => 'Unauthorized', 404 => 'Not Found', 500 => 'Internal Server Error', 503 => 'Service Unavailable' };
	my $content = $options->{'message'};
	$content .= ": $options->{'details'}" if $options->{'details'};
	$status_desc->{ $options->{'status'} } = q() if $options->{'no_status_desc'};
	Dancer2::Core::Error->new(
		response => response(),
		title    => "Error $options->{'status'} $status_desc->{$options->{'status'}} - $options->{'message'}",
		status   => $options->{'status'},
		message  => $content,
		app      => app()
	)->throw;
	halt();
	return;
}

sub _is_authorized {
	my ($self) = @_;
	$self->_cookie_login;
	my $route = request->uri;
	if ( session('user') ) {
		my $user_info = $self->{'datastore'}->get_user_info_from_username( session('user') );
		session full_name => "$user_info->{'first_name'} $user_info->{'surname'}";
		my $config_access    = $self->is_user_allowed_access( session('user') );
		my $user_permissions = $self->{'datastore'}->get_permissions( session('user') );
		if ( $user_permissions->{'disable_access'} ) {
			$self->throw_error(
				{
					status  => 401,
					message => 'Access disabled',
					details => 'Your user account has been disabled. If you believe this to be an error, '
					  . 'please contact the system administrator.',
				}
			);
		} elsif ( !$config_access ) {
			$self->throw_error(
				{
					status  => 401,
					message => 'Access denied',
					details => 'Your user account cannot access this database configuration. If you believe this to '
					  . 'be an error, please contact the system administrator.',
				}
			);
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

sub _password_reset_required {
	my ( $self, $session, $username ) = @_;
	return $self->{'datastore'}->run_query(
		'SELECT EXISTS(SELECT * FROM sessions WHERE (dbase,session,state,username)=(?,md5(?),?,?) AND reset_password)',
		[ $self->{'system'}->{'db'}, $session, 'active', $username ],
		{ db => $self->{'auth_db'}, cache => 'Login::password_reset_required' }
	);
}

sub get_guid {

	#If the user is logged in, use a combination of database and user names as the
	#GUID for preference storage, otherwise use a random GUID which is stored as a browser cookie.
	my ($self) = @_;
	if ( defined session('user') ) {
		return "$self->{'system'}->{'db'}\|" . session('user');
	} elsif ( $self->get_cookie('guid') ) {
		return $self->get_cookie('guid');
	} else {
		return 0;
	}
}

sub get_field_selection_list {

	#options passed as hashref:
	#isolate_fields: include isolate fields, prefix with f_
	#extended_attributes: include isolate field extended attributes, named e_FIELDNAME||EXTENDED-FIELDNAME
	#loci: include loci, prefix with either l_ or cn_ (common name)
	#locus_limit: don't include loci if there are more than the set value
	#query_pref: only the loci for which the user has a query field preference selected will be returned
	#analysis_pref: only the loci for which the user has an analysis preference selected will be returned
	#scheme_fields: include scheme fields, prefix with s_SCHEME-ID_
	#classification_groups: include classification group ids and field, prefix with cg_
	#sort_labels: dictionary sort labels
	my ( $self, $options ) = @_;
	$logger->logdie('Invalid option hashref') if ref $options ne 'HASH';
	$options->{'query_pref'}    //= 1;
	$options->{'analysis_pref'} //= 0;
	my $values = [];
	if ( $options->{'isolate_fields'} ) {
		my $isolate_fields = $self->_get_provenance_fields($options);
		push @$values, @$isolate_fields;
	}
	if ( $options->{'loci'} ) {
		my $loci = $self->_get_loci_list($options);
		push @$values, @$loci;
	}
	if ( $options->{'scheme_fields'} ) {
		my $scheme_fields = $self->_get_scheme_fields($options);
		push @$values, @$scheme_fields;
	}
	if ( $options->{'classification_groups'} ) {
		my $classification_group_fields = $self->_get_classification_groups_fields;
		push @$values, @$classification_group_fields;
	}
	if ( $options->{'sort_labels'} ) {
		$values = BIGSdb::Utils::dictionary_sort( $values, $self->{'cache'}->{'labels'} );
	}
	return $values, $self->{'cache'}->{'labels'};
}

sub _get_provenance_fields {
	my ( $self, $options ) = @_;
	my @isolate_list;
	my $set_id        = $self->get_set_id;
	my $metadata_list = $self->{'datastore'}->get_set_metadata( $set_id, { curate => $self->{'curate'} } );
	my $fields        = $self->{'xmlHandler'}->get_field_list($metadata_list);
	my $attributes    = $self->{'xmlHandler'}->get_all_field_attributes;
	my $extended      = $options->{'extended_attributes'} ? $self->get_extended_attributes : undef;
	foreach my $field (@$fields) {

		if (   ( $options->{'sender_attributes'} )
			&& ( $field eq 'sender' || $field eq 'curator' || ( $attributes->{$field}->{'userfield'} // '' ) eq 'yes' )
		  )
		{
			foreach my $user_attribute (qw (id surname first_name affiliation)) {
				push @isolate_list, "f_$field ($user_attribute)";
				( $self->{'cache'}->{'labels'}->{"f_$field ($user_attribute)"} = "$field ($user_attribute)" ) =~
				  tr/_/ /;
			}
		} else {
			push @isolate_list, "f_$field";
			my ( $metaset, $metafield ) = $self->get_metaset_and_fieldname($field);
			( $self->{'cache'}->{'labels'}->{"f_$field"} = $metafield // $field ) =~ tr/_/ /;
			if ( $options->{'extended_attributes'} ) {
				my $extatt = $extended->{$field};
				if ( ref $extatt eq 'ARRAY' ) {
					foreach my $extended_attribute (@$extatt) {
						push @isolate_list, "e_$field||$extended_attribute";
						( $self->{'cache'}->{'labels'}->{"e_$field||$extended_attribute"} = $extended_attribute ) =~
						  tr/_/ /;
					}
				}
			}
		}
	}
	return \@isolate_list;
}

sub get_extended_attributes {
	my ($self) = @_;
	my $data =
	  $self->{'datastore'}
	  ->run_query( 'SELECT isolate_field,attribute FROM isolate_field_extended_attributes ORDER BY field_order',
		undef, { fetch => 'all_arrayref', slice => {}, cache => 'Page::get_extended_attributes' } );
	my $extended;
	foreach (@$data) {
		push @{ $extended->{ $_->{'isolate_field'} } }, $_->{'attribute'};
	}
	return $extended;
}

sub get_metaset_and_fieldname {
	my ( $self, $field ) = @_;
	my ( $metaset, $metafield ) = $field =~ /meta_([^:]+):(.*)/x ? ( $1, $2 ) : ( undef, undef );
	return ( $metaset, $metafield );
}

sub initiate_prefs {
	my ( $self, $options ) = @_;
	return if !$self->{'prefstore'};
	my ( $general_prefs, $field_prefs, $scheme_field_prefs );
	my $guid = $self->get_guid || 1;
	try {
		$self->{'prefstore'}->update_datestamp($guid);
	}
	catch {
		undef $self->{'prefstore'};

		#		$self->{'fatal'} = 'prefstoreConfig';
	};
	return if !$options->{'general'} && !$options->{'query_field'};
	return if !$self->{'prefstore'};
	my $dbname = $self->{'system'}->{'db'};
	$field_prefs = $self->{'prefstore'}->get_all_field_prefs( $guid, $dbname );
	$scheme_field_prefs = $self->{'prefstore'}->get_all_scheme_field_prefs( $guid, $dbname );
	if ( $options->{'general'} ) {
		$general_prefs = $self->{'prefstore'}->get_all_general_prefs( $guid, $dbname );
		$self->{'prefs'}->{'displayrecs'} = $general_prefs->{'displayrecs'} // 25;
		$self->{'prefs'}->{'pagebar'}     = $general_prefs->{'pagebar'}     // 'top and bottom';
		$self->{'prefs'}->{'alignwidth'}  = $general_prefs->{'alignwidth'}  // 100;
		$self->{'prefs'}->{'flanking'}    = $general_prefs->{'flanking'}    // 100;
		foreach (
			qw(set_id submit_allele_technology submit_allele_read_length
			submit_allele_coverage submit_allele_assembly submit_allele_software)
		  )
		{
			$self->{'prefs'}->{$_} = $general_prefs->{$_};
		}

		#default off
		foreach (qw (hyperlink_loci )) {
			$general_prefs->{$_} //= 'off';
			$self->{'prefs'}->{$_} = $general_prefs->{$_} eq 'on' ? 1 : 0;
		}

		#default on
		foreach (qw (tooltips submit_email)) {
			$general_prefs->{$_} //= 'on';
			$self->{'prefs'}->{$_} = $general_prefs->{$_} eq 'off' ? 0 : 1;
		}
	}
	if ( $self->{'system'}->{'dbtype'} eq 'isolates' ) {
		$self->_initiate_isolatedb_prefs( $options, $general_prefs, $field_prefs, $scheme_field_prefs );
	}

	#Set dropdown status for scheme fields
	if ( $options->{'query_field'} ) {
		my $scheme_ids =
		  $self->{'datastore'}->run_query( 'SELECT id FROM schemes', undef, { fetch => 'col_arrayref' } );
		my $scheme_fields              = $self->{'datastore'}->get_all_scheme_fields;
		my $scheme_field_default_prefs = $self->{'datastore'}->get_all_scheme_field_info;
		foreach my $scheme_id (@$scheme_ids) {
			foreach ( @{ $scheme_fields->{$scheme_id} } ) {
				foreach my $action (qw(dropdown)) {
					if ( defined $scheme_field_prefs->{$scheme_id}->{$_}->{$action} ) {
						$self->{'prefs'}->{"$action\_scheme_fields"}->{$scheme_id}->{$_} =
						  $scheme_field_prefs->{$scheme_id}->{$_}->{$action} ? 1 : 0;
					} else {
						$self->{'prefs'}->{"$action\_scheme_fields"}->{$scheme_id}->{$_} =
						  $scheme_field_default_prefs->{$scheme_id}->{$_}->{$action};
					}
				}
			}
		}
	}
	$self->{'datastore'}->update_prefs( $self->{'prefs'} );
	return;
}

sub _initiate_isolatedb_prefs {
	my ( $self, $options, $general_prefs, $field_prefs, $scheme_field_prefs ) = @_;
	my $set_id           = $self->get_set_id;
	my $metadata_list    = $self->{'datastore'}->get_set_metadata($set_id);
	my $field_list       = $self->{'xmlHandler'}->get_field_list($metadata_list);
	my $field_attributes = $self->{'xmlHandler'}->get_all_field_attributes;
	my $extended         = $self->get_extended_attributes;
	my $args             = {
		field_list       => $field_list,
		field_prefs      => $field_prefs,
		extended         => $extended,
		field_attributes => $field_attributes
	};

	#Parameters set by preference store via session cookie
	my $guid = $self->get_guid || 1;
	my $dbname = $self->{'system'}->{'db'};
	$self->_initiate_isolatedb_general_prefs($general_prefs) if $options->{'general'};
	$self->_initiate_isolatedb_query_field_prefs($args)      if $options->{'query_field'};
	$self->_initiate_isolatedb_main_display_prefs($args)     if $options->{'main_display'};
	return if none { $options->{$_} } qw (isolate_display main_display query_field analysis);
	$self->_initiate_isolatedb_locus_prefs( $options, $guid, $dbname );
	$self->_initiate_isolatedb_scheme_prefs( $guid, $dbname, $field_prefs, $scheme_field_prefs );
	return;
}

sub _initiate_isolatedb_general_prefs {
	my ( $self, $general_prefs ) = @_;

	#default off
	foreach my $option (
		qw (update_details allele_flags scheme_members_alias sequence_details_main
		display_seqbin_main display_contig_count display_publications)
	  )
	{
		$general_prefs->{$option} //= 'off';
		$self->{'prefs'}->{$option} = $general_prefs->{$option} eq 'on' ? 1 : 0;
	}

	#default on
	foreach my $option (qw (sequence_details sample_details mark_provisional mark_provisional_main)) {
		$general_prefs->{$option} //= 'on';
		$self->{'prefs'}->{$option} = $general_prefs->{$option} eq 'off' ? 0 : 1;
	}

	#Locus aliases - default off
	my $default_locus_aliases = ( $self->{'system'}->{'locus_aliases'} // '' ) eq 'yes' ? 1 : 0;
	$general_prefs->{'locus_alias'} //= 'off';
	$self->{'prefs'}->{'locus_alias'} = $general_prefs->{'locus_alias'} eq 'on' ? 1 : $default_locus_aliases;
	return;
}

sub _initiate_isolatedb_query_field_prefs {
	my ( $self, $args ) = @_;
	my ( $field_list, $field_prefs, $field_attributes, $extended ) =
	  @{$args}{qw(field_list field_prefs field_attributes extended)};
	foreach my $field (@$field_list) {
		next if $field eq 'id';
		if ( defined $field_prefs->{$field}->{'dropdown'} ) {
			$self->{'prefs'}->{'dropdownfields'}->{$field} = $field_prefs->{$field}->{'dropdown'};
		} else {
			$field_attributes->{$field}->{'dropdown'} ||= 'no';
			$self->{'prefs'}->{'dropdownfields'}->{$field} = $field_attributes->{$field}->{'dropdown'} eq 'yes' ? 1 : 0;
		}
		my $extatt = $extended->{$field};
		if ( ref $extatt eq 'ARRAY' ) {
			foreach my $extended_attribute (@$extatt) {
				if ( defined $field_prefs->{$field}->{'dropdown'} ) {
					$self->{'prefs'}->{'dropdownfields'}->{"${field}..$extended_attribute"} =
					  $field_prefs->{"${field}..$extended_attribute"}->{'dropdown'};
				} else {
					$self->{'prefs'}->{'dropdownfields'}->{"${field}..$extended_attribute"} = 0;
				}
			}
		}
	}
	if ( defined $field_prefs->{'Publications'}->{'dropdown'} ) {
		$self->{'prefs'}->{'dropdownfields'}->{'Publications'} = $field_prefs->{'Publications'}->{'dropdown'};
	} else {
		$self->{'prefs'}->{'dropdownfields'}->{'Publications'} =
		  ( $self->{'system'}->{'no_publication_filter'} // '' ) eq 'yes' ? 0 : 1;
	}
	return;
}

sub _initiate_isolatedb_main_display_prefs {
	my ( $self, $args ) = @_;
	my ( $field_list, $field_prefs, $field_attributes, $extended ) =
	  @{$args}{qw(field_list field_prefs field_attributes extended)};
	if ( defined $field_prefs->{'aliases'}->{'maindisplay'} ) {
		$self->{'prefs'}->{'maindisplayfields'}->{'aliases'} = $field_prefs->{'aliases'}->{'maindisplay'};
	} else {
		$self->{'system'}->{'maindisplay_aliases'} ||= 'no';
		$self->{'prefs'}->{'maindisplayfields'}->{'aliases'} =
		  $self->{'system'}->{'maindisplay_aliases'} eq 'yes' ? 1 : 0;
	}
	foreach my $field (@$field_list) {
		next if $field eq 'id';
		if ( defined $field_prefs->{$field}->{'maindisplay'} ) {
			$self->{'prefs'}->{'maindisplayfields'}->{$field} = $field_prefs->{$field}->{'maindisplay'};
		} else {
			$field_attributes->{$field}->{'maindisplay'} ||= 'yes';
			$self->{'prefs'}->{'maindisplayfields'}->{$field} =
			  $field_attributes->{$field}->{'maindisplay'} eq 'no' ? 0 : 1;
		}
		my $extatt = $extended->{$field};
		if ( ref $extatt eq 'ARRAY' ) {
			foreach my $extended_attribute (@$extatt) {
				if ( defined $field_prefs->{$field}->{'maindisplay'} ) {
					$self->{'prefs'}->{'maindisplayfields'}->{"${field}..$extended_attribute"} =
					  $field_prefs->{"${field}..$extended_attribute"}->{'maindisplay'};
				} else {
					$self->{'prefs'}->{'maindisplayfields'}->{"${field}..$extended_attribute"} = 0;
				}
			}
		}
	}
	my $qry = 'SELECT id,main_display FROM composite_fields';
	my $sql = $self->{'db'}->prepare($qry);
	eval { $sql->execute };
	$logger->logdie($@) if $@;
	while ( my ( $id, $main_display ) = $sql->fetchrow_array ) {
		if ( defined $field_prefs->{$id}->{'maindisplay'} ) {
			$self->{'prefs'}->{'maindisplayfields'}->{$id} = $field_prefs->{$id}->{'maindisplay'};
		} else {
			$self->{'prefs'}->{'maindisplayfields'}->{$id} = $main_display ? 1 : 0;
		}
	}
	return;
}

sub _initiate_isolatedb_locus_prefs {
	my ( $self, $options, $guid, $dbname ) = @_;
	my $locus_prefs =
	  $self->{'datastore'}->run_query( 'SELECT id,isolate_display,main_display,query_field,analysis FROM loci',
		undef, { fetch => 'all_arrayref' } );
	my $prefstore_values = $self->{'prefstore'}->get_all_locus_prefs( $guid, $dbname );
	my $i = 1;
	foreach my $action (qw (isolate_display main_display query_field analysis)) {
		if ( !$options->{$action} ) {
			$i++;
			next;
		}
		my $term = "${action}_loci";
		foreach my $locus_pref (@$locus_prefs) {
			my $locus = $locus_pref->[0];
			if ( defined $prefstore_values->{$locus}->{$action} ) {
				if ( $action eq 'isolate_display' ) {
					$self->{'prefs'}->{$term}->{$locus} = $prefstore_values->{$locus}->{$action};
				} else {
					$self->{'prefs'}->{$term}->{$locus} = $prefstore_values->{$locus}->{$action} eq 'true' ? 1 : 0;
				}
			} else {
				$self->{'prefs'}->{$term}->{$locus} = $locus_pref->[$i];
			}
		}
		$i++;
	}
	return;
}

sub _initiate_isolatedb_scheme_prefs {
	my ( $self, $guid, $dbname, $field_prefs, $scheme_field_prefs ) = @_;
	my $scheme_ids = $self->{'datastore'}->run_query( 'SELECT id FROM schemes', undef, { fetch => 'col_arrayref' } );
	my $scheme_values              = $self->{'prefstore'}->get_all_scheme_prefs( $guid, $dbname );
	my $scheme_field_default_prefs = $self->{'datastore'}->get_all_scheme_field_info;
	my $scheme_info                = $self->{'datastore'}->get_all_scheme_info;
	my $scheme_fields              = $self->{'datastore'}->get_all_scheme_fields;
	foreach my $scheme_id (@$scheme_ids) {
		foreach my $action (qw(isolate_display main_display query_field query_status analysis)) {
			if ( defined $scheme_values->{$scheme_id}->{$action} ) {
				$self->{'prefs'}->{"$action\_schemes"}->{$scheme_id} = $scheme_values->{$scheme_id}->{$action} ? 1 : 0;
			} else {
				$self->{'prefs'}->{"$action\_schemes"}->{$scheme_id} = $scheme_info->{$scheme_id}->{$action};
			}
		}
		if ( ref $scheme_fields->{$scheme_id} eq 'ARRAY' ) {
			foreach my $field ( @{ $scheme_fields->{$scheme_id} } ) {
				foreach my $action (qw(isolate_display main_display query_field)) {
					if ( defined $scheme_field_prefs->{$scheme_id}->{$field}->{$action} ) {
						$self->{'prefs'}->{"${action}_scheme_fields"}->{$scheme_id}->{$field} =
						  $scheme_field_prefs->{$scheme_id}->{$field}->{$action} ? 1 : 0;
					} else {
						$self->{'prefs'}->{"${action}_scheme_fields"}->{$scheme_id}->{$field} =
						  $scheme_field_default_prefs->{$scheme_id}->{$field}->{$action};
					}
				}
			}
		}
		my $field = "scheme_$scheme_id\_profile_status";
		if ( defined $field_prefs->{$field}->{'dropdown'} ) {
			$self->{'prefs'}->{'dropdownfields'}->{$field} = $field_prefs->{$field}->{'dropdown'};
		} else {
			$self->{'prefs'}->{'dropdownfields'}->{$field} = $self->{'prefs'}->{'query_status_schemes'}->{$scheme_id};
		}
	}
	return;
}

sub _setup_prefstore {
	my ($self) = @_;
	my %att = (
		dbase_name => $self->{'config'}->{'prefs_db'},
		host       => $self->{'system'}->{'host'},
		port       => $self->{'system'}->{'port'},
		user       => $self->{'system'}->{'user'},
		password   => $self->{'system'}->{'password'},
	);
	my $pref_db;
	try {
		$pref_db = $self->{'dataConnector'}->get_connection( \%att );
	}
	catch {
		$self->throw_error( { status => 500, message => 'Cannot connect to preferences database!' } );
	};
	$self->{'prefstore'} = BIGSdb2::Preferences->new( db => $pref_db );
	return;
}
1;
