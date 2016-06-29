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
package BIGSdb2::WebApp::About;
use strict;
use warnings;
use 5.010;
use Log::Log4perl qw(get_logger);
my $logger = get_logger('BIGSdb.Page');
use Dancer2 appname => 'BIGSdb2::WebApplication';
get '/' => sub { _about() };
get '/:db/about' => sub { _about( { db => 1 } ) };

sub _about {
	my ($options) = @_;
	my $self      = setting('self');
	my $version   = '2 pre-alpha';
	my $pg_version = $options->{'db'} ? $self->{'datastore'}->run_query('SELECT version()') : undef;

	#Set version number in binary file when released.
	my $params = { title => "BIGSdb Version $version", version => $version, pg_version => $pg_version };
	return template 'about.tt', $params;
}
1;
