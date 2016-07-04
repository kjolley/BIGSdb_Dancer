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
package BIGSdb2::WebApp::Public::Query;
use strict;
use warnings;
use 5.010;
use Log::Log4perl qw(get_logger);
my $logger = get_logger('BIGSdb.Page');
use Dancer2 appname => 'BIGSdb2::WebApplication';
use Dancer2::Plugin::Ajax;
use BIGSdb2::Constants qw(OPERATORS);
get '/:db/query' => sub {
	my $self = setting('self');
	if ( $self->{'system'}->{'dbtype'} eq 'isolates' ) {
		return _isolate_query();
	}
	return;
};
ajax '/:db/provenance_fields/:element' => sub {
	return template 'public/query/provenance.tt',
	  { i => params->{'element'}, operators => [OPERATORS], provenance_items => _get_provenance_items() };
};

sub _isolate_query {
	my $self = setting('self');
	my $desc = $self->get_db_description;
	$self->initiate_prefs( { general => 1, main_display => 1, isolate_display => 0, analysis => 0, query_field => 1 } );
	my $title = $self->{'curate'} ? 'Isolate query/update' : "Search or browse $desc database";
	my $params = {
		title     => $title,
		help_link => "$self->{'config'}->{'doclink'}/curator_guide.html#"
		  . 'updating-and-deleting-single-isolate-records',
		tooltips                    => 1,
		javascript                  => $self->get_javascript_libs( [qw(jQuery noCache jQuery.multiselect)] ),
		submit                      => $self->get_action_fieldset,
		provenance_fieldset_display => 'inline',
		provenance_elements         => 1,
		provenance_items            => _get_provenance_items()
	};
	$self->add_route_params($params);
	return template 'public/query.tt', $self->{'route_params'};
}

sub _get_provenance_items {
	my $self = setting('self');
	my ( $field_list, $labels ) =
	  $self->get_field_selection_list( { isolate_fields => 1, sender_attributes => 1, extended_attributes => 1 } );
	my $items = [];
	foreach my $field (@$field_list) {
		push @$items, { field => $field, label => $labels->{$field} };
		if ( $field eq "f_$self->{'system'}->{'labelfield'}" ) {
			my $grouped = $self->{'xmlHandler'}->get_grouped_fields;
			foreach my $field (@$grouped) {
				( my $label = $field ) =~ tr/_/ /;
				push @$items, { field => "f_$field", label => $label };
			}
		}
	}
	return $items;
}
1;
