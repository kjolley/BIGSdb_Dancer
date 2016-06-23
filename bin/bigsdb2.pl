#!/usr/bin/perl
#bigsdb.pl
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
use strict;
use warnings;
use 5.010;
###########Local configuration################################
use constant { CONFIG_DIR => '/etc/bigsdb' };
#######End Local configuration################################
use Log::Log4perl qw(get_logger);
use FindBin;
use lib "$FindBin::Bin/../lib";
use BIGSdb2::Application;
Log::Log4perl->init_once( CONFIG_DIR . '/logging.conf' );
my $app = BIGSdb2::Application->new(
	{ config_dir => CONFIG_DIR }
);
$app->dance;
