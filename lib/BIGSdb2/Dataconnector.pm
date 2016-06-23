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
package BIGSdb2::Dataconnector;
use strict;
use warnings;
use feature 'state';
use Log::Log4perl qw(get_logger);
my $logger = get_logger('BIGSdb.Dataconnector');

sub new {
	my ($class) = @_;
	my $self = {};
	$self->{'db'} = {};
	bless( $self, $class );
	return $self;
}

sub DESTROY {
	my ($self) = @_;
	$self->drop_all_connections;
	return;
}

sub _finish_active_statement_handles {
	my ( $self, $h, $level ) = @_;
	if ( $h->{'Active'} && $h->{'Type'} eq 'st' ) {
		eval { $h->finish };
		$logger->error($@) if $@;
		$logger->debug("Active statement: $h->{'Statement'}");
	}
	$self->_finish_active_statement_handles( $_, $level + 1 ) for ( grep { defined } @{ $h->{'ChildHandles'} } );
	return;
}

sub initiate {

	#set system attributes (can't be done in constructor as this is called before configuration files are read)
	my ( $self, $system, $config ) = @_;
	$self->{'system'} = $system;
	$self->{'config'} = $config;
	return;
}

sub drop_connection {
	my ( $self, $attributes ) = @_;
	my $host = $attributes->{'host'} || $self->{'system'}->{'host'};
	return if !$attributes->{'dbase_name'};
	if ( $self->{'db'}->{"$attributes->{'host'}|$attributes->{'dbase_name'}"} ) {
		$self->_finish_active_statement_handles( $self->{'db'}->{"$attributes->{'host'}|$attributes->{'dbase_name'}"},
			1 );
		$self->{'db'}->{"$attributes->{'host'}|$attributes->{'dbase_name'}"}->disconnect;
	}
	undef $self->{'db'}->{"$attributes->{'host'}|$attributes->{'dbase_name'}"};
	return;
}

sub drop_all_connections {
	my ($self) = @_;
	foreach my $db ( keys %{ $self->{'db'} } ) {
		$self->_finish_active_statement_handles( $self->{'db'}->{$db}, 1 );
		eval {
			$self->{'db'}->{$db}->disconnect
			  and $logger->info("Disconnected from database $self->{'db'}->{$db}->{'Name'}");
		};
		delete $self->{'db'}->{$db};
	}
	return;
}

sub get_connection {
	my ( $self, $attributes ) = @_;
	my $host     = $attributes->{'host'}     || $self->{'system'}->{'host'};
	my $port     = $attributes->{'port'}     || $self->{'system'}->{'port'};
	my $user     = $attributes->{'user'}     || $self->{'system'}->{'user'};
	my $password = $attributes->{'password'} || $self->{'system'}->{'password'};
	$host = $self->{'config'}->{'host_map'}->{$host} || $host;
	throw BIGSdb::DatabaseConnectionException('No database name passed') if !$attributes->{'dbase_name'};
	state $pid = $$;

	if ( !$self->{'db'}->{"$host|$attributes->{'dbase_name'}"} ) {
		my $db;
		eval {
			$db = DBI->connect( "DBI:Pg:host=$host;port=$port;dbname=$attributes->{'dbase_name'}",
				$user, $password, { AutoCommit => 0, RaiseError => 1, PrintError => 0, pg_enable_utf8 => 1 } );
			$self->{'db'}->{"$host|$attributes->{'dbase_name'}"} = $db;
		};
		if ($@) {
			$logger->error("Can not connect to database '$attributes->{'dbase_name'}' ($host). $@");
			throw BIGSdb::DatabaseConnectionException(
				"Can not connect to database '$attributes->{'dbase_name'}' ($host)");
		} else {
			$logger->info("Connected to database $attributes->{'dbase_name'} ($host)");
			$logger->debug(
				"dbase: $attributes->{'dbase_name'}; host: $host; port: $port: user: $user; password: $password");
		}
		if (BIGSdb2::Utils::is_int($self->{'config'}->{'temp_buffers'})){
			$db->do("SET temp_buffers='$self->{'config'}->{'temp_buffers'}MB'");
		}
	}

	#Properly handle forked environment (used for scanning)
	$self->{'db'}->{"$host|$attributes->{'dbase_name'}"}->{'InactiveDestroy'} = $pid == $$ ? 1 : 0;
	return $self->{'db'}->{"$host|$attributes->{'dbase_name'}"};
}
1;
