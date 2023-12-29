WHEN GIVEN A FILE TO WORK WITH, DO NOT FORGET TO RUN THIS STEGHIDE WITH AN EMPTY PASSWORD!

* `steghide` - [Website](http://steghide.sourceforge.net/)

	Hide data in various kinds of image- and audio-files using a passphrase.

* `AperiSolve` :heart: - [Website](https://www.aperisolve.com/)

	Online tool that run several steganography tools.

* `StegCracker` - [GitHub](https://github.com/Paradoxis/StegCracker)

	Brute force passphrases for steghide encrypted files. Different data can have different passphrases.

* `Steganography Online` - [Website](http://stylesuxx.github.io/steganography/)

	Online tool to hide data in images.

* `StegSeek` - [GitHub](https://github.com/RickdeJager/stegseek)

	Faster than `stegcracker`.

* `steg_brute.py` - [GitHub](https://github\.com/Va5c0/Steghide-Brute-Force-Tool)

	This is similar to `stegcracker`.

* `Stegsolve.jar` :heart: - [Website](http://www.caesum.com/handbook/stego.htm) 

	View the image in different colorspaces and alpha channels. I recommend using [this patched version](https://github.com/Giotino/stegsolve) to be able to zoom out.


* `stepic` - [Website](http://domnit.org/stepic/doc/)

	Python library to hide data in images.

* [`APNG`]

	Animated PNG. Use (apngdis)[https://sourceforge.net/projects/apngdis/] to extract the frames and delays.

* `SVG Layers`

	You can hide data in hidden layers in SVG files. `inkview` can be used to view and toggle the layers.

* `Digital Invisible Ink Tool` - [Website](http://diit.sourceforge.net/)

	A Java steganography tool that can hide any sort of file inside a digital image (regarding that the message will fit, and the image is 24 bit color)


* `ImageHide` - [Website](https://www.softpedia.com/get/Security/Encrypting/ImageHide.shtml)

	Hide any data in the LSB of an image. Can have a password.

* `stegoVeritas` - [GitHub](https://github.com/bannsec/stegoVeritas/)

	CLI tool to extract data from images.

* Unicode Steganography / Zero-Width Space Characters

	Messages can be hidden in the unicode characters. For example using the zero-width space character in it. Use a modern IDE like [Code](https://code.visualstudio.com/) to find these characters.

* Online LSB Tools

	Some online tools to hide data in the LSB of images.

	[https://manytools.org/hacker-tools/steganography-encode-text-into-image/](https://manytools.org/hacker-tools/steganography-encode-text-into-image/) Only supports PNG
	[https://stylesuxx.github.io/steganography/](https://stylesuxx.github.io/steganography/)

* Other stego tools:

	[https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

* `zsteg` :heart: - [GitHub](https://github\.com/zed-0xff/zsteg)

	Command-line tool for **PNG** and **BMP** steganography.

* `jsteg` - [GitHub](https://github\.com/lukechampine/jsteg)

    Command-line tool for **JPEG** steganography.

* [Jstego](https://sourceforge.net/projects/jstego/)

    GUI tool for **JPG** steganography.

* `openstego` - [Website](https://www.openstego.com/)

	Steganography tool.

* Morse Code

	Morse code can be everywhere.

* Whitespace

	Tabs and spaces (for example in the indentation) can hide data. Some tools can find it: [`snow`](http://www.darkside.com.au/snow/) or an esoteric programming language interpreter: [https://tio.run/#whitespace](https://tio.run/#whitespace)

* `snow` - [Website](http://www.darkside.com.au/snow/)

	A command-line tool for whitespace steganography.

* `exiftool` :heart: - [Website](https://exiftool.org/)

	Tool to view and edit metadata in files.

* Extract Thumbnail (data is covered in original image)

	If you have an image where the data you need is covered, try viewing the thumbnail:

	```
	exiftool -b -ThumbnailImage my_image.jpg > my_thumbnail.jpg
	```

* `spectrogram` - [Wikipedia](https://en.wikipedia.org/wiki/Spectrogram)

	An image can be hidden in the spectrogram of an audio file. [`audacity`](https://www.audacityteam.org/) can show the spectrogram of an audio file. (To select Spectrogram view, click on the track name (or the black triangle) in the Track Control Panel which opens the Track Dropdown Menu, where the spectrogram view can be selected.. )

* `XIAO Steganography` - [Website](https://xiao-steganography.en.softonic.com/)

	Windows software to hide data in audio.

* `DTMF` - [Wikipedia](https://en.wikipedia.org/wiki/Dual-tone_multi-frequency_signaling).

	Dual tone multi-frequency is a signaling system using the voice-frequency band over telephone lines. It can be used to send text messages over the phone. Some tool: [Detect DTMF Tones](http://dialabc.com/sound/detect/index.html) 
	

* Phone-Keypad

	Letters can be encoded with numbers using a phone keypad.

![https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQSySxHjMFv80XWp74LZpfrnAro6a1MLqeF1F3zpguA5PGSW9ov](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQSySxHjMFv80XWp74LZpfrnAro6a1MLqeF1F3zpguA5PGSW9ov)

* `hipshot` - [Website](https://bitbucket.org/eliteraspberries/hipshot)

	A python tool to hide a video in an image.

* `QR code` - [Wikipedia](https://en.wikipedia.org/wiki/QR_code) 
	
	Square barcode that can store data.

* `zbarimg` - [Website](https://linux.die.net/man/1/zbarimg)

	CLI tool to scan QR codes of different types.


* Corrupted image files

	See [Images forensics](../Forensics/Images/README.md)
