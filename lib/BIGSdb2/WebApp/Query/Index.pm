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
package BIGSdb2::WebApp::Query::Index;
use strict;
use warnings;
use 5.010;
use Log::Log4perl qw(get_logger);
my $logger = get_logger('BIGSdb.Page');
use Dancer2 appname => 'BIGSdb2::WebApplication';
get '/:db' => sub { _print_index() };

sub _print_index {
	my $self   = setting('self');
	my $set_id = $self->get_set_id;
	my $scheme_data =
	  $self->{'datastore'}
	  ->get_scheme_list( { with_pk => ( $self->{'system'}->{'dbtype'} eq 'sequences' ? 1 : 0 ), set_id => $set_id } );
	my $params = {
		title      => $self->{'system'}->{'description'},
		desc       => $self->get_db_description() || 'BIGSdb',
		banner     => $self->get_file_text("$self->{'config_dir'}/dbases/$self->{'instance'}/banner.html"),
		query      => _get_query_items($scheme_data),
		general    => _get_general_items($scheme_data),
		javascript => $self->get_javascript_libs( [qw(jQuery)] )
	};
	return template 'index.tt', $params;
}

sub _get_query_items {
	my ($scheme_data) = @_;
	my $self          = setting('self');
	my $items         = [];
	my $root          = "/$self->{'instance'}";
	my $set_id        = $self->get_set_id;
	if ( $self->{'system'}->{'dbtype'} eq 'isolates' ) {
		push @$items, { label => q(Search or browse database), uri => uri_for("$root/query") };
		my $loci = $self->{'datastore'}->get_loci( { set_id => $set_id, do_not_order => 1 } );
		if (@$loci) {
			push @$items, { label => q(Search by combinations of loci (profiles)) };
		}
	} elsif ( $self->{'system'}->{'dbtype'} eq 'sequences' ) {
		push @$items, { label => q(Sequence query),       comment => q(query an allele sequence) };
		push @$items, { label => q(Batch sequence query), comment => q(query multiple sequences in FASTA format) };
		push @$items,
		  {
			label   => q(Sequence attribute search),
			comment => q(find alleles by matching criteria (all loci together))
		  };
		push @$items,
		  {
			label   => q(Locus-specific sequence attribute),
			comment => q(select, analyse and download specific alleles)
		  };
		if (@$scheme_data) {

			#Specify scheme_id if only one defined, otherwise use a general URI
			my $scheme_desc = @$scheme_data == 1 ? $scheme_data->[0]->{'description'} : q();
			push @$items, { label => qq(Search, browse or enter list of $scheme_desc profiles) };
			push @$items,
			  { label => qq(Search by combinations of $scheme_desc alleles), comment => q(including partial matching) };
			push @$items,
			  {
				label   => q(Batch profile query),
				comment => qq(lookup $scheme_desc profiles copied from a spreadsheet)
			  };
		}
	}

	#TODO Rule queries
	if ( $self->{'system'}->{'dbtype'} eq 'isolates' ) {
		my $projects = $self->{'datastore'}->run_query('SELECT COUNT(*) FROM projects WHERE list');
		push @$items, { label => q(Projects), comment => q(main projects defined in database) } if $projects;
	}
	return $items;
}

sub _get_general_items {
	my ($scheme_data) = @_;
	my $self          = setting('self');
	my $items         = [];
	my $max_date;
	if ( $self->{'system'}->{'dbtype'} eq 'sequences' ) {
		my $allele_count = _get_allele_count();
		push @$items, { label => qq(Number of sequences: $allele_count) };
		my $tables = [qw (locus_stats profiles profile_refs accession)];
		$max_date = _get_max_date($tables);
		if ( @$scheme_data == 1 ) {
			foreach (@$scheme_data) {
				my $profile_count =
				  $self->{'datastore'}
				  ->run_query( 'SELECT COUNT(*) FROM profiles WHERE scheme_id=?', $scheme_data->[0]->{'id'} );
				push @$items, { label => qq(Number of profiles ($scheme_data->[0]->{'description'}): $profile_count) };
			}
		} elsif ( @$scheme_data > 1 ) {
			my $item = { label => q(Number of profiles), hidelist => 1 };
			my $hide_list = [];
			foreach my $scheme (@$scheme_data) {
				my $profile_count =
				  $self->{'datastore'}->run_query( 'SELECT COUNT(*) FROM profiles WHERE scheme_id=?', $scheme->{'id'} );
				$scheme->{'description'} =~ s/\&/\&amp;/gx;
				push @$hide_list, { label => qq($scheme->{'description'}: $profile_count) };
			}
			$item->{'hidelist'} = $hide_list;
			push @$items, $item;
		}
	} else {
		my $count = $self->{'datastore'}->run_query("SELECT COUNT(*) FROM $self->{'system'}->{'view'}");
		push @$items, { label => qq(Isolates: $count) };
		my $tables = [qw (isolates isolate_aliases allele_designations allele_sequences refs)];
		$max_date = _get_max_date($tables);
	}
	push @$items, { label => qq(Last updated: $max_date) };

	#TODO Update history links
	if ( $self->{'system'}->{'dbtype'} eq 'sequences' ) {

	 #		push @$items, { label => q(Profile update history), uri => uri_for("/$self->{'instance'}/tableQuery/history") };
	} else {

		#		push @$items, { label => q(Update history), uri => uri_for("/$self->{'instance'}/tableQuery/history") };
	}
	push @$items, { label => q(About BIGSdb), uri => uri_for("/$self->{'instance'}/about") };
	return $items;
}

sub _get_max_date {
	my ($tables) = @_;
	my $self = setting('self');
	local $" = ' UNION SELECT MAX(datestamp) FROM ';
	my $qry      = "SELECT MAX(max_datestamp) FROM (SELECT MAX(datestamp) AS max_datestamp FROM @$tables) AS v";
	my $max_date = $self->{'datastore'}->run_query($qry);
	return $max_date;
}

sub _get_allele_count {
	my $self   = setting('self');
	my $set_id = $self->get_set_id;
	my $set_clause =
	  $set_id
	  ? ' WHERE locus IN (SELECT locus FROM scheme_members WHERE scheme_id IN (SELECT scheme_id FROM '
	  . "set_schemes WHERE set_id=$set_id)) OR locus IN (SELECT locus FROM set_loci WHERE set_id=$set_id)"
	  : q();
	return $self->{'datastore'}->run_query("SELECT SUM(allele_count) FROM locus_stats$set_clause") // 0;
}
1;
