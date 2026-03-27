.PHONY: test pack

test:
	python3 -m compileall bbx.py

pack:
	cd .. && zip -r bbx.zip bbx
