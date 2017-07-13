Intel ME 11.x Firmware Images Unpacker
=====
This repository contains Python 2.7 scripts for unpacking firmware regions for ME 11.x

## Usage

  unME11.py <ME_Image_File_Name.bin>

  Report would be written to ME_Image_File_Name.txt

  Extracted data (partitions, modules, metadata) would be written to ME_Image_File_Name folder

  Compiled lzma binary is required on PATH for LMZA decompression (see [http://www.7-zip.org/download.html][1])

## Limitations

  No progress output. Don't worry - just wait

  Huffman tables are incompete [yet]. unME11 would crash on unknown Huffman sequences (it is expected behaviour ;)

## Related URLs:

[Intel ME: The Way of the Static Analysis][2]

[Intel DCI Secrets][3]

## Author

Dmitry Sklyarov ([@_Dmit][6])

## Research Team

Mark Ermolov ([@\_markel___][4])

Maxim Goryachy ([@h0t_max][5])

Dmitry Sklyarov ([@_Dmit][6])

## License
This software is provided under a custom License. See the accompanying LICENSE file for more information.

[1]: http://www.7-zip.org/download.html
[2]: https://www.troopers.de/troopers17/talks/772-intel-me-the-way-of-the-static-analysis/
[3]: http://conference.hitb.org/hitbsecconf2017ams/sessions/commsec-intel-dci-secrets/
[4]: https://twitter.com/_markel___
[5]: https://twitter.com/h0t_max
[6]: https://twitter.com/_Dmit
