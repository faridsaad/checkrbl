#!/usr/bin/perl -w
# Farid Saad (farid.saad@rackspace.com)
use Mail::RBL;
use CGI qw(:standard :cgi-lib);
use Net::DNS;
use Net::SMTP;
use DBI;
use strict;

my $cgi = new CGI;
my %parameters = $cgi->Vars;
my $host;
my %color = (
          green  => "\e[32;1m",
          yellow => "\e[33;1m",
          red    => "\e[31;1m",
          gray   => "\e[30;1m",
          white  => "\e[37;1m",
          red    => "\e[31;1m",
          blue   => "\e[34;1m",
          reset  => "\e[0m",
);
my $agent = $ENV{HTTP_USER_AGENT};
my $failstatus = 0;

if($agent){
    unless($agent =~ /curl/){
        print "Status: 301 Moved Permanently\n";
        print "Location: http://checkrbl.com/site/\n\n";
        exit;
    }
}
print $cgi->header('text/html');

# Works with Varnish!
# Make sure Varnish is setting up X_FORWARDED_FOR header, and pipe'ing the request if you want this script to work.
if($ENV{HTTP_X_FORWARDED_FOR}){
    $host = (split /,/, $ENV{HTTP_X_FORWARDED_FOR})[0];
} else {
    $host = $ENV{REMOTE_ADDR};
}



print "$color{'white'}===================================$color{'reset'}\n";
print "$color{'white'}checkrbl.pl - Comments, suggestions and bug reports: farid.saad\@rackspace.com$color{'reset'}\n";
print "$color{'white'}IP CHECK FOR $color{'yellow'}${host}$color{'reset'}\n";
print "$color{'white'}===================================$color{'reset'}\n";

# Is this IP listed in RBL lists?
print "\n$color{'white'}RBL Checks\n-----------------------------------$color{'reset'}\n";
my %rbls = (
		'SpamCop' => 'bl.spamcop.net',
		'SpamHaus XBL' => 'xbl.spamhaus.org',
		'SpamHaus SBL' => 'sbl.spamhaus.org',
                'SpamHaus PBL' => 'pbl.spamhaus.org',
		'UCE-Protect' => 'dnsbl-1.uceprotect.net',
		'SORBS'       => 'dnsbl.sorbs.net',
		'Backscatterer'  => 'ips.backscatterer.org',
		'Barracuda Central' => 'b.barracudacentral.org',
		'Mail-Abuse' => 'relays.mail-abuse.org',
		'SORBS Open SOCKS proxy' => 'socks.dnsbl.sorbs.net',
		'SORBS Open Relay server' => 'smtp.dnsbl.sorbs.net'
	   );


foreach my $entry (sort keys %rbls){
	my $list = new Mail::RBL($rbls{$entry});
	if (my ($ip_result, $optional_info_txt) = $list->check($host)) {
                $failstatus = 1;
		print "   $color{'white'} *** $color{'red'}IS LISTED$color{'reset'} in $entry\n";
	} else {
		print " - not listed in $entry\n";
	}
}

# Reverse record present?
print "\n$color{'white'}Reverse Record Check\n-----------------------------------$color{'reset'}\n";
my $dnsres = Net::DNS::Resolver->new;
my $ptr_query = $dnsres->query($host, "PTR");
my $ptrname;

if($ptr_query){
	my $r = ($ptr_query->answer)[0];
	if($r->type ne "PTR") { die "not PTR"; }
                $ptrname = $r->rdatastr;
                chop ($ptrname);
		print "Reverse Record present: $ptrname\n";
} else {
        $failstatus = 1;;
	print "This IP address DOES NOT have a reverse record.\n";
}


# Verify SMTP settings if port open
print "\n$color{'white'}SMTP port check\n-----------------------------------$color{'reset'}\n";
my $smtp = Net::SMTP->new($host,
		       Timeout => 3);
if (defined($smtp)){
	my $mailbanner = $smtp->domain();
	print "Connected to $host on port 25, mail banner says: $color{'white'}$mailbanner$color{'reset'}.\n";
	$smtp->quit;

# If SMTP open, verify banner resolves in DNS
	my $a_query = $dnsres->query($mailbanner, "A");
	if($a_query){
		my $a_rec = ($a_query->answer)[0];
		if($a_rec->type ne "A") { 
                        print "\nBAD: $mailbanner doesn't have an 'A' record or it's a CNAME, needs to be fixed.\n\n"; 
                        $failstatus = 1;
                        exit 
                }
                        my $dnsip = $a_rec->rdatastr;
			print "Found 'A' Record for $mailbanner: $dnsip\n";
                        if ($dnsip eq $host){
                            print "DNS 'A' record for $mailbanner matches the given IP $host\n";
                            if ($ptrname eq $mailbanner){
                                print "\n$color{'white'}Results\n-----------------------------------\n$color{'white'}GOOD:$color{'reset'} Reverse record matches SMTP banner, 3-way mailcheck $color{'green'}PASS.$color{'reset'}\n\n";
                            } else {
                                print "\n$color{'white'}Results\n-----------------------------------\n$color{'white'}BAD:$color{'reset'} Reverse record DOES NOT match SMTP banner, 3-way mailcheck $color{'red'}FAILED.$color{'reset'}\n\n";
                                $failstatus = 1;
                            }
                        } else {
                            print "\n$color{'white'}Results\n-----------------------------------\n$color{'white'}BAD:$color{'reset'} DNS 'A' record for $mailbanner DOES NOT match your IP $host. 3-way mailcheck $color{'red'}FAILED.$color{'reset'}\n\n";
                            $failstatus = 1;
                        }

         
	} else {
		print "\n$color{'white'}Results\n-----------------------------------\n$color{'white'}BAD:$color{'reset'} The hostname $mailbanner IS NOT present in DNS! 3-way mailcheck $color{'red'}FAILED.$color{'reset'}\n\n";
                $failstatus = 1;
	}

} else {
        $failstatus = 1;
	print "$color{'white'}Unable to connect to $host on port 25$color{'reset'}\n\n";
}
