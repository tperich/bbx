.PHONY: test pack

test:
	python3 -m compileall bbx.py

pack:
	cd .. && zip -r bb_sqlite_toolkit_pro.zip bb_sqlite_toolkit_pro
