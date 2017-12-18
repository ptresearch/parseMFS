Intel ME File System Explorer
=====
This repository contains Python 2.7 scripts for parsing MFS/MFSB partition and extracting contained files.

## Usage

  parseMFS.py <MFS_Partition_File_Name.bin>

  Extracted files would be stored in MFS_Partition_File_Name.bin.zip file

## Limitations

  Tested with MFS partitions obtained from ME 11.x firmware images

## Related URLs:

[Intel ME: Flash File System Explained][1]

[Intel ME: The Way of the Static Analysis][2]

[Intel DCI Secrets][3]

[How to Hack a Turned-Off Computer or Running Unsigned Code in Intel Management Engine][4]

[Intel ME 11.x Firmware Images Unpacker][8]

## Author

Dmitry Sklyarov ([@_Dmit][7])

## Research Team

Mark Ermolov ([@\_markel___][5])

Maxim Goryachy ([@h0t_max][6])

Dmitry Sklyarov ([@_Dmit][7])

## License
This software is provided under a custom License. See the accompanying LICENSE file for more information.

[1]: https://www.blackhat.com/eu-17/briefings.html#intel-me-flash-file-system-explained
[2]: https://www.troopers.de/troopers17/talks/772-intel-me-the-way-of-the-static-analysis/
[3]: http://conference.hitb.org/hitbsecconf2017ams/sessions/commsec-intel-dci-secrets/
[4]: https://www.blackhat.com/eu-17/briefings.html#how-to-hack-a-turned-off-computer-or-running-unsigned-code-in-intel-management-engine
[5]: https://twitter.com/_markel___
[6]: https://twitter.com/h0t_max
[7]: https://twitter.com/_Dmit
[8]: https://github.com/ptresearch/unME11
