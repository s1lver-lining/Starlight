* `Android Studio` - [Website](https://developer.android.com/studio)

    Main IDE for Android development. Java and Kotlin can be used.

* `jadx` :heart: - [GitHub](https://github.com/skylot/jadx)

    Decompiles Android APKs to Java source code. Comes with a GUI.

	```bash
	jadx -d "$(pwd)/out" "$(pwd)/<app>" # Decompile the APK to a folder
	```

* `apktool` - [Website](https://ibotpeaches.github.io/Apktool/)

	A command-line tool to extract all the resources from an APK file.

	```bash
	apktool d <file.apk> # Extracts the APK to a folder
	```


* `dex2jar` - [GitHub](https://github.com/pxb1988/dex2jar)

	A command-line tool to convert a J.dex file to .class file and zip them as JAR files.


* `jd-gui` - [GitHub](https://github.com/java-decompiler/jd-gui)

	A GUI tool to decompile Java code, and JAR files.
