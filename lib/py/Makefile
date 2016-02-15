all: images rpc.py

.PHONY: all images clean

images:
	$(Q) $(MAKE) -C images all

# rpc_pb2.py doesn't depend on any other file, so
# it is safe to rename it, dropping ugly _pb2 suffix.
rpc.py:
	$(Q) protoc -I=$(SRC_DIR)/protobuf/ --python_out=./ $(SRC_DIR)/protobuf/$(@:.py=.proto)
	$(Q) mv $(@:.py=_pb2.py) $@

clean:
	$(Q) $(MAKE) -C images clean
	$(Q) $(RM) rpc.py *.pyc
