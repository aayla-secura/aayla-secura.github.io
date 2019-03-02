#!/usr/bin/env perl
use strict;
use warnings;
use Getopt::Std;

sub usage {
  print "$0 [-i <outline_file>] [-m <motto_file>] [-o <output_basename>]";
  exit 0;
}

my %options=();
getopts("hai:o:m:", \%options);
usage() if defined $options{h};
my $outline_fname = (defined $options{i}) ? $options{i} : "out/logo_outline.txt";
my $motto_fname = (defined $options{m}) ? $options{m} : "motto.txt";
my $logo_basename = (defined $options{o}) ? $options{o} : "out/logo";
my $html = "1";
if (defined $options{a} or ((split /\.([^\.]+)$/, $outline_fname)[1]) eq "txt") {
  $html = "";
};

# read in files
my $logo = undef;
my $motto = undef;
do {
  local $/ = undef; # read whole input, not just one line

  open my $fh, '<', $outline_fname or die "error opening $outline_fname $!";
  $logo = <$fh>;
  close $fh;

  open $fh, '<', $motto_fname or die "error opening $motto_fname $!";
  $motto = <$fh>;
  close $fh;
};

(my $charset = $motto) =~ s!(.)!sprintf "%02x",ord($1)!egs;

sub nextcharsinit {
    my $pos = 0;
    return sub {
        my $len = $_[0];
        my $s = substr $charset, $pos, $len;
        my $left =  $pos + $len - length $charset;
        while ($left >= 0) {
          # wrapped around
          $pos = 0;
          $len = $left;
          $s .= substr $charset, $pos, $len;
          $left -= length $charset;
        };
        $pos += $len;
        return $s;
    };
}

my $nextchars = nextcharsinit();
my $bgcol = "white";
$logo =~ s!\r!!g;
if ($html) {
  print "Processing as HTML\n";
  # replace text in the bgcol color with equivalent number of spaces
  $logo =~ s!<font color="?$bgcol"?>([a-f0-9]+)</font>!" " x length $1!eg;
  # replace the rest of the text with equivalent number of characters from the
  # character set, at the current position in the charset
  $logo =~ s!<font color=[^>]+>([a-f0-9]+)</font>!$nextchars->(length $1) . ""!eg;
  $logo =~ s!</? *br */?>!\n!g; # add newlines
  $logo =~ s!<[^>]+>!!g; # remove left over html tags
  $logo =~ s!^ *(\n|\z)!!gm; # delete blank lines
} else { # ascii
  print "Processing as ASCII\n";
  $logo =~ s!([^ \n]+)!$nextchars->(length $1) . ""!eg;
}

do {
  # txt
  open my $fh, '>', $logo_basename . '.txt';
  print $fh $logo;
  close $fh;

  # svg
  my $text = "";
  my @logolines = split /\n/, $logo;
  ## calculate the stepY to get approx 1:1 aspect ratio
  my $stepY = 100/(1+@logolines); # in percentage
  my $currY = $stepY;
  my $w = length($logolines[0]); # all lines have the same no. of chars
  foreach my $line (@logolines) {
    # replace space with transparent 0's; alternatively set style to white-space: pre
    $line =~ s!( +)!"<tspan>" . ("0" x length $1) . "</tspan>"!eg;
    $text .= <<"EOF";
  <text x="0" y="$currY%">
  $line
  </text>
EOF
    $currY += $stepY;
  }

  open $fh, '>', $logo_basename . '.svg';
  # at 16px monospace, the width should be 10xno. of chars
  print $fh <<"EOF";
<svg viewBox="0 0 ${w}0 ${w}0" xmlns="http://www.w3.org/2000/svg">
  <style>
    text {
      font: bold 16px monospace;
    }
    tspan {
      fill: none;
      draw: none;
    }
  </style>
$text
</svg>
EOF
  close $fh;
};

print "Saved to $logo_basename.txt and $logo_basename.svg\n";
