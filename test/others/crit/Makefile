run: clean
	@make -C .. loop
	./test.sh

clean:
	rm -f *.img *.log *.txt stats-* *.json
	rm -rf comp/ uncomp/ cdc/ dcd/ region/ sparse-compress/ sparse-decompress/
	rm -rf threshold-compress/ threshold-parent/ parent-placeholder/ truncated-decompress/
	rm -rf malformed-*/ transaction-compress/ transaction-decompress/
