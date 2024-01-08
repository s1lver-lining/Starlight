[PNG](https://en.wikipedia.org/wiki/Portable_Network_Graphics) is a raster graphics file format that supports lossless data compression.


## Tools

* PNG data after IEND chunk in cropped image

    Badly cropped PNG image can leave the cropped data after the IEND chunk. This can be spotted when there are two IEND chunks in a file. This can leak data from the original image, such as in the `aCropalypse` (CVE-2023-21036) vulnerability.

    [This github repository](https://github.com/Absenti/acropalypse_png) can help to extract the data. [This GUI tool](https://github.com/frankthetank-music/Acropalypse-Multi-Tool) can also be used.