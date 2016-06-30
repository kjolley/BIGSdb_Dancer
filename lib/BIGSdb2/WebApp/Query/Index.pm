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
		query => _get_query_section($scheme_data),
		general    => _get_general_info_section($scheme_data),
		javascript => $self->get_javascript_libs( [qw(jQuery)] )
	};
	return template 'index.tt', $params;
}

sub _get_query_section {
	my ($scheme_data) = @_;
	my $self          = setting('self');
	my $items = [];
	my $root = "/$self->{'instance'}";
	if ( $self->{'system'}->{'dbtype'} eq 'isolates' ) {
		push @$items, {label => q(Search or browse database), uri => uri_for("$root/query")};
#		my $loci = $self->{'datastore'}->get_loci( { set_id => $set_id, do_not_order => 1 } );
#		if (@$loci) {
#			say qq(<li><a href="${url_root}page=profiles">Search by combinations of loci (profiles)</a></li>);
#		}
#	} elsif ( $system->{'dbtype'} eq 'sequences' ) {
#		say qq(<li><a href="${url_root}page=sequenceQuery">Sequence query</a> - query an allele sequence.</li>);
#		say qq(<li><a href="${url_root}page=batchSequenceQuery">Batch sequence query</a> - )
#		  . q(query multiple sequences in FASTA format.</li>);
#		say qq(<li><a href="${url_root}page=tableQuery&amp;table=sequences">Sequence attribute search</a> - )
#		  . q(find alleles by matching criteria (all loci together)</li>);
#		say qq(<li><a href="${url_root}page=alleleQuery&amp;table=sequences">Locus-specific sequence attribute )
#		  . q(search</a> - select, analyse and download specific alleles.</li>);
#		if (@$scheme_data) {
#			my $scheme_arg  = @$scheme_data == 1 ? "&amp;scheme_id=$scheme_data->[0]->{'id'}" : '';
#			my $scheme_desc = @$scheme_data == 1 ? $scheme_data->[0]->{'description'}         : '';
#			say qq(<li><a href="${url_root}page=query$scheme_arg">Search, browse or enter list of )
#			  . qq($scheme_desc profiles</a></li>);
#			say qq(<li><a href="${url_root}page=profiles$scheme_arg">Search by combinations of $scheme_desc )
#			  . q(alleles</a> - including partial matching.</li>);
#			say qq(<li><a href="${url_root}page=batchProfiles$scheme_arg">Batch profile query</a> - )
#			  . qq(lookup $scheme_desc profiles copied from a spreadsheet.</li>);
#		}
	}
#	if ( $self->{'config'}->{'jobs_db'} ) {
#		my $query_html_file = "$self->{'system'}->{'dbase_config_dir'}/$self->{'instance'}/contents/job_query.html";
#		$self->print_file($query_html_file) if -e $query_html_file;
#	}
#	if ( $system->{'dbtype'} eq 'isolates' ) {
#		my $projects = $self->{'datastore'}->run_query('SELECT COUNT(*) FROM projects WHERE list');
#		say qq(<li><a href="${url_root}page=projects">Projects</a> - main projects defined in database.) if $projects;
#		my $sample_fields = $self->{'xmlHandler'}->get_sample_field_list;
#		if (@$sample_fields) {
#			say qq(<li><a href="${url_root}page=tableQuery&amp;table=samples">Sample management</a> - )
#			  . q(culture/DNA storage tracking</li>);
#		}
#	}
	return $items;
}

sub _get_general_info_section {
	my ($scheme_data) = @_;
	my $self          = setting('self');
	my $items         = [];
	my $max_date;
	if ( $self->{'system'}->{'dbtype'} eq 'sequences' ) {
		my $allele_count = _get_allele_count();
		push @$items, qq(Number of sequences: $allele_count);
		my $tables = [qw (locus_stats profiles profile_refs accession)];
		$max_date = _get_max_date($tables);
		if ( @$scheme_data == 1 ) {
			foreach (@$scheme_data) {
				my $profile_count =
				  $self->{'datastore'}
				  ->run_query( 'SELECT COUNT(*) FROM profiles WHERE scheme_id=?', $scheme_data->[0]->{'id'} );
				push @$items, qq(Number of profiles ($scheme_data->[0]->{'description'}): $profile_count);
			}
		} elsif ( @$scheme_data > 1 ) {
			my $buffer = q(Number of profiles: <a id="toggle1" class="showhide">Show</a>)
			  . q(<a id="toggle2" class="hideshow">Hide</a><div class="hideshow"><ul>);
			foreach (@$scheme_data) {
				my $profile_count =
				  $self->{'datastore'}->run_query( 'SELECT COUNT(*) FROM profiles WHERE scheme_id=?', $_->{'id'} );
				$_->{'description'} =~ s/\&/\&amp;/gx;
				$buffer .= qq(<li>$_->{'description'}: $profile_count</li>);
			}
			$buffer .= q(</ul></div>);
			push @$items, $buffer;
		}
	} else {
		my $count = $self->{'datastore'}->run_query("SELECT COUNT(*) FROM $self->{'system'}->{'view'}");
		push @$items, qq(Isolates: $count);
		my $tables = [qw (isolates isolate_aliases allele_designations allele_sequences refs)];
		$max_date = _get_max_date($tables);
	}
	push @$items, qq(Last updated: $max_date);
	if ( $self->{'system'}->{'dbtype'} eq 'sequences' ) {
		my $history = uri_for("/$self->{'instance'}/tableQuery/history");
		push @$items, qq(<a href="$history">Profile update history</a>);
	} else {
		my $history = uri_for("/$self->{'instance'}/tableQuery/history");
		push @$items, qq(<a href="$history">Update history</a>);
	}
	my $about = uri_for("/$self->{'instance'}/about");
	push @$items, qq(<a href="$about">About BIGSdb</a>);
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
