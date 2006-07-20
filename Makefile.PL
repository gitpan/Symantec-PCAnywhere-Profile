use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Symantec::PCAnywhere::Profile',
    AUTHOR              => 'Darren Kulp <darren@kulp.ch>',
    VERSION_FROM        => 'lib/Symantec/PCAnywhere/Profile.pm',
    ABSTRACT_FROM       => 'lib/Symantec/PCAnywhere/Profile.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Carp' => 0,
        'Compress::Zlib' => 0,
        'Digest::MD5' => 0,
        'MIME::Base64' => 0,
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Symantec-PCAnywhere-Profile-*' },
);
