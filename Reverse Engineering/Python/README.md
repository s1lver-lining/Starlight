
* `Decompile .pyc files`

	Several software can be used to decompile python bytecode.

	| Software | Source | Notes |
	| --- | --- | --- |
	| `uncompyle6` | [GitHub](https://github\.com/rocky/python-uncompyle6/) | Decompiles Python bytecode to equivalent Python source code. Support python versions **up to to 3.8**. Legend has it that it exists an option (maybe -d) that can succeed when the regular decompilation fails. |
	| `Decompyle++` :heart: | [GitHub](https://github.com/zrax/pycdc) | Less reliable, but can decompile every python3 versions. |
	| `Easy Python Decompiler` | [Website](https://sourceforge.net/projects/easypythondecompiler/) | Windows GUI to decompile python bytecode. |


* `Pyinstaller Extractor` - [GitHub](https://github.com/extremecoders-re/pyinstxtractor)

	Extracts the python bytecode from pyinstaller windows executables. Can be decomplied  after.

	```bash
	python3 pyinstxtractor.py <filename>
	```

	An alternative is `pydumpck`