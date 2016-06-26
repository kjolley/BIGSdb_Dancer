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
use BIGSdb2::Dataconnector;
use BIGSdb2::Datastore;
use BIGSdb2::Parser;
use BIGSdb2::Utils;

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
	$self->initiate;

	#	set behind_proxy => $self->{'config'}->{'rest_behind_proxy'} ? 1 : 0;
	return $self;
}

#Override in subclass
sub initiate { }

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

sub get_file_text {
	my ( $self, $filename ) = @_;
	if ( -e $filename ) {
		my $text_ref = BIGSdb2::Utils::slurp($filename);
		return $$text_ref;
	}
	return q();
}
1;
