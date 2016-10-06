all: images rpc_pb2.py

.PHONY: all images clean

images:
	$(Q) $(MAKE) -C images all

rpc_pb2.py:
	$(Q) protoc -I=$(SRC_DIR)/images/ --python_out=./ $(SRC_DIR)/images/$(@:_pb2.py=.proto)

clean:
	$(Q) $(MAKE) -C images clean
	$(Q) $(RM) rpc_pb2.py *.pyc
