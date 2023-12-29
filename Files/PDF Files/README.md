
* `pdfinfo` - [Website](https://poppler.freedesktop.org/)

	A command-line tool to get a basic synopsis of what the [PDF](https://en.wikipedia.org/wiki/Portable_Document_Format) file is.

	```bash
	# Extract all javascript from a PDF file
	pdfinfo -js input.pdf
	```

* `pdf-parser` :heart: - [Website](https://blog.didierstevens.com/programs/pdf-tools/)

	Parse a PDF file and extract the objects.

	```bash
	# Extract stream from object 77
	python pdf-parser.py -o 77 -f -d out.txt input.pdf
	```

* `qpdf` - [GitHub](https://github\.com/qpdf/qpdf)

	A command-line tool to manipulate [PDF](https://en.wikipedia.org/wiki/Portable_Document_Format) files. Can extract embedded files.

* `pdfcrack` - [Website](https://pdfcrack.sourceforge.net/)

	A command-line tool to recover a password from a PDF file. Supports dictionary, wordlists, and bruteforce.

* `pdfimages` - [Website](https://poppler.freedesktop.org/)

	A command-line tool, the first thing to reach for when given a PDF file. It extracts the images stored in a PDF file, but it needs the name of an output directory (that it will create for) to place the found images.

* `pdfdetach` - [Website](https://www.systutorials.com/docs/linux/man/1-pdfdetach/)

	A command-line tool to extract files out of a [PDF](https://en.wikipedia.org/wiki/Portable_Document_Format) file.