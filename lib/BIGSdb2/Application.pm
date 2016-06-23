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
package BIGSdb2::Application;
use strict;
use warnings;
use 5.010;
use Dancer2;
use Config::Tiny;
use Try::Tiny;
use List::MoreUtils qw(uniq);
use Log::Log4perl qw(get_logger);
my $logger = get_logger('BIGSdb.Application_Initiate');
use DBI;
use BIGSdb2::Constants qw(:interface);
use BIGSdb2::Dataconnector;
use BIGSdb2::Datastore;
use BIGSdb2::Parser;
use BIGSdb2::Utils;
use BIGSdb2::Routes::Login;
use BIGSdb2::Routes::Query::Index;
hook before                 => sub { _before() };
hook after                  => sub { _after() };
hook before_template_render => sub { _before_template() };

sub new {
	my ( $class, $options ) = @_;
	my $self = {};
	$self->{'system'}            = {};
	$self->{'config'}            = {};
	$self->{'instance'}          = undef;
	$self->{'xmlHandler'}        = undef;
	$self->{'dataConnector'}     = BIGSdb2::Dataconnector->new;
	$self->{'datastore'}         = undef;
	$self->{'submissionHandler'} = undef;
	$self->{'db'}                = undef;
	$self->{'config_dir'}        = $options->{'config_dir'};
	bless( $self, $class );
	$self->_initiate;

	#	set behind_proxy => $self->{'config'}->{'rest_behind_proxy'} ? 1 : 0;
	set self => $self;
	return $self;
}

sub _initiate {
	my ($self) = @_;
	$self->read_config_file( $self->{'config_dir'} );
	$self->read_host_mapping_file( $self->{'config_dir'} );
	set template => 'template_toolkit';
	set views    => path( dirname(__FILE__), '../../templates' );
	set layout   => 'main';
	return;
}

sub read_config_file {
	my ( $self, $config_dir ) = @_;
	my $config = Config::Tiny->new();
	$config = Config::Tiny->read("$config_dir/bigsdb.conf");
	foreach my $param (
		qw ( prefs_db auth_db jobs_db rest_db max_load emboss_path tmp_dir secure_tmp_dir submission_dir
		blast+_path blast_threads muscle_path max_muscle_mb mafft_path mafft_threads mogrify_path ipcress_path
		splitstree_path reference refdb ref_db chartdirector disable_updates disable_update_message intranet
		debug results_deleted_days cache_days doclink rest_behind_proxy bcrypt_cost curate_script query_script
		submissions_deleted_days smtp_server stylesheet domain max_upload_size temp_buffers)
	  )
	{
		$self->{'config'}->{$param} = $config->{_}->{$param};
	}

	#Check integer values
	foreach my $param (
		qw(max_load blast_threads bcrypt_cost mafft_threads results_deleted_days cache_days submissions_deleted_days))
	{
		if ( defined $self->{'config'}->{$param} && !BIGSdb2::Utils::is_int( $self->{'config'}->{$param} ) ) {
			$logger->error("Parameter $param in bigsdb.conf should be an integer - default value used.");
			undef $self->{'config'}->{$param};
		}
	}

	#Check float values
	foreach my $param (qw(max_upload_size max_muscle_mb)) {
		if ( defined $self->{'config'}->{$param} && !BIGSdb2::Utils::is_float( $self->{'config'}->{$param} ) ) {
			$logger->error("Parameter $param in bigsdb.conf should be a number - default value used.");
			undef $self->{'config'}->{$param};
		}
	}
	$self->{'config'}->{'intranet'}   //= 'no';
	$self->{'config'}->{'cache_days'} //= 7;
	if ( $self->{'config'}->{'chartdirector'} ) {
		eval 'use perlchartdir';    ## no critic (ProhibitStringyEval)
		if ($@) {
			$logger->error(q(Chartdirector not installed! - Either install or set 'chartdirector=0' in bigsdb.conf));
			$self->{'config'}->{'chartdirector'} = 0;
		} else {
			eval 'use BIGSdb2::Charts';    ## no critic (ProhibitStringyEval)
			if ($@) {
				$logger->error('Charts.pm not installed!');
			}
		}
	}
	$self->{'config'}->{'aligner'} = 1 if $self->{'config'}->{'muscle_path'} || $self->{'config'}->{'mafft_path'};
	$self->{'config'}->{'doclink'}         //= 'http://bigsdb.readthedocs.io/en/latest';
	$self->{'config'}->{'max_upload_size'} //= 32;
	$self->{'config'}->{'max_upload_size'} *= 1024 * 1024;
	$self->_read_db_config_file($config_dir);
	return;
}

sub _read_db_config_file {
	my ( $self, $config_dir ) = @_;
	my $db_file = "$config_dir/db.conf";
	if ( !-e $db_file ) {
		return;
	}
	my $config = Config::Tiny->new();
	$config = Config::Tiny->read($db_file);
	foreach my $param (qw (dbhost dbport dbuser dbpassword)) {
		$self->{'config'}->{$param} = $config->{_}->{$param};
	}
	if ( defined $self->{'config'}->{'dbport'} && !BIGSdb2::Utils::is_int( $self->{'config'}->{'dbport'} ) ) {
		$logger->error('Parameter dbport in db.conf should be an integer - default value used.');
		undef $self->{'config'}->{'dbport'};
	}
	return;
}

sub read_host_mapping_file {
	my ( $self, $config_dir ) = @_;
	my $mapping_file = "$config_dir/host_mapping.conf";
	if ( -e $mapping_file ) {
		open( my $fh, '<', $mapping_file )
		  || get_logger('BIGSdb.Application_Initiate')->error("Can't open $mapping_file for reading");
		while (<$fh>) {
			next if /^\s+$/x || /^\#/x;
			my ( $host, $mapped ) = split /\s+/x, $_;
			next if !$host || !$mapped;
			$self->{'config'}->{'host_map'}->{$host} = $mapped;
		}
		close $fh;
	}
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
	my $login_route = "/$self->{'instance'}/login";
	my $logout_route = "/$self->{'instance'}/logout";

	#	my $submission_route = "/db/$self->{'instance'}/submissions";
	#	if ( $request_uri =~ /$submission_route/x ) {
	#		$self->setup_submission_handler;
	#	}
	if ( ( $authenticated_db && $request_uri !~ /^$login_route/x && $request_uri !~ /^$logout_route/x) ) {
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

sub set_system_overrides {
	my ($self) = @_;
	my $override_file = "$self->{'config_dir'}/dbases/$self->{'instance'}/system.overrides";
	if ( -e $override_file ) {
		open( my $fh, '<', $override_file )
		  || get_logger('BIGSdb.Application_Initiate')->error("Can't open $override_file for reading");
		while ( my $line = <$fh> ) {
			next if $line =~ /^\#/x;
			$line =~ s/^\s+//x;
			$line =~ s/\s+$//x;
			if ( $line =~ /^([^=\s]+)\s*=\s*"([^"]+)"$/x ) {
				$self->{'system'}->{$1} = $2;
			}
		}
		close $fh;
	}
	return;
}

sub db_connect {
	my ($self) = @_;
	my %att = (
		dbase_name => $self->{'system'}->{'db'},
		host       => $self->{'system'}->{'host'},
		port       => $self->{'system'}->{'port'},
		user       => $self->{'system'}->{'user'},
		password   => $self->{'system'}->{'password'}
	);
	try {
		$self->{'db'} = $self->{'dataConnector'}->get_connection( \%att );
	}
	catch {
		$logger->error("Can not connect to database '$self->{'system'}->{'db'}'");
	};
	return;
}

sub initiate_authdb {
	my ($self) = @_;
	my %att = (
		dbase_name => $self->{'config'}->{'auth_db'},
		host       => $self->{'system'}->{'host'},
		port       => $self->{'system'}->{'port'},
		user       => $self->{'system'}->{'user'},
		password   => $self->{'system'}->{'password'},
	);
	try {
		$self->{'auth_db'} = $self->{'dataConnector'}->get_connection( \%att );
		$logger->info("Connected to authentication database '$self->{'config'}->{'auth_db'}'");
	}
	catch {
		$logger->error("Can not connect to authentication database '$self->{'config'}->{'auth_db'}'");
		$self->{'error'} = 'noAuth';
	};
	return;
}

sub setup_datastore {
	my ($self) = @_;
	$self->{'datastore'} = BIGSdb2::Datastore->new(
		db            => $self->{'db'},
		dataConnector => $self->{'dataConnector'},
		system        => $self->{'system'},
		config        => $self->{'config'},
		xmlHandler    => $self->{'xmlHandler'}
	);
	return;
}

sub get_db_description {
	my ($self) = @_;
	my $desc = $self->{'system'}->{'description'};
	return $desc if $self->{'system'}->{'sets'} && $self->{'system'}->{'set_id'};
	my $set_id = $self->get_set_id;
	if ($set_id) {
		my $desc_ref =
		  $self->{'datastore'}->run_query( 'SELECT * FROM sets WHERE id=?', $set_id, { fetch => 'row_hashref' } );
		$desc .= ' (' . $desc_ref->{'description'} . ')' if $desc_ref->{'description'} && !$desc_ref->{'hidden'};
	}
	$desc =~ s/\&/\&amp;/gx;
	return $desc;
}

sub get_set_id {
	my ($self) = @_;
	if ( ( $self->{'system'}->{'sets'} // '' ) eq 'yes' ) {
		my $set_id = $self->{'system'}->{'set_id'} // $self->{'prefs'}->{'set_id'};
		return $set_id if $set_id && BIGSdb::Utils::is_int($set_id);
	}
	if ( ( $self->{'system'}->{'only_sets'} // '' ) eq 'yes' && !$self->{'curate'} ) {
		if ( !$self->{'cache'}->{'set_list'} ) {
			$self->{'cache'}->{'set_list'} =
			  $self->{'datastore'}->run_query( 'SELECT id FROM sets ORDER BY display_order,description',
				undef, { fetch => 'col_arrayref' } );
		}
		return $self->{'cache'}->{'set_list'}->[0] if @{ $self->{'cache'}->{'set_list'} };
	}
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

sub _is_authorized {
	my ($self) = @_;
	return 1 if session('user');
	my $route = request->uri;

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

sub get_file_text {
	my ( $self, $filename ) = @_;
	if ( -e $filename ) {
		my $text_ref = BIGSdb2::Utils::slurp($filename);
		return $$text_ref;
	}
	return q();
}

sub get_action_fieldset {
	my ( $self, $options ) = @_;
	my $q = $self->{'cgi'};
	$options = {} if ref $options ne 'HASH';

	#	my $page         = $options->{'page'}         // $q->param('page');
	my $submit_label = $options->{'submit_label'} // 'Submit';
	my $reset_label  = $options->{'reset_label'}  // 'Reset';
	my $legend       = $options->{'legend'}       // 'Action';
	my $buffer       = qq(<fieldset style="float:left"><legend>$legend</legend>\n);

	#	my $url    = qq($self->{'system'}->{'script_name'}?db=$self->{'instance'}&amp;page=$page);
	my $url    = request->uri;
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
1;
